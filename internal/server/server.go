// Package server binds the resolver to the network: an authoritative DNS
// responder over UDP and TCP (RFC 1035 §4.2, including the two-byte
// length framing and TC-bit truncation for oversized UDP answers). The
// request→response transform is a pure function over bytes, so the whole
// protocol path is testable without opening a socket.
package server

import (
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/JaydenCJ/hostwild/internal/dnswire"
	"github.com/JaydenCJ/hostwild/internal/resolver"
)

// tcpReadTimeout bounds how long an idle TCP client may hold a
// connection.
const tcpReadTimeout = 10 * time.Second

// Server answers DNS queries using one resolver.
type Server struct {
	Resolver *resolver.Resolver
	Logger   *log.Logger // nil = silent

	mu   sync.Mutex
	udp  net.PacketConn
	tcp  net.Listener
	done bool
}

func (s *Server) logf(format string, args ...any) {
	if s.Logger != nil {
		s.Logger.Printf(format, args...)
	}
}

// HandleQuery is the pure request→response transform. It never returns
// an empty slice for a syntactically addressable query: malformed
// messages that still carry a header ID get FORMERR, non-queries get
// NOTIMP. Only garbage too short to echo an ID yields nil (drop).
func (s *Server) HandleQuery(req []byte, udpLimit int) []byte {
	if len(req) < 12 {
		return nil // cannot even echo an ID; drop silently
	}
	msg, err := dnswire.Decode(req)
	if err != nil {
		// Salvage the ID and flags straight from the header bytes.
		id := binary.BigEndian.Uint16(req[0:2])
		return mustEncode(&dnswire.Message{Header: dnswire.Header{
			ID: id, QR: true, RCode: dnswire.RCodeFormErr,
		}})
	}
	resp := &dnswire.Message{Header: dnswire.Header{
		ID: msg.Header.ID, QR: true, AA: true,
		Opcode: msg.Header.Opcode, RD: msg.Header.RD,
	}}
	switch {
	case msg.Header.QR:
		return nil // a response, not a query; never answer answers
	case msg.Header.Opcode != dnswire.OpcodeQuery:
		resp.Header.RCode = dnswire.RCodeNotImp
	case len(msg.Questions) != 1:
		resp.Header.RCode = dnswire.RCodeFormErr
	default:
		q := msg.Questions[0]
		resp.Questions = msg.Questions
		res := s.Resolver.Resolve(q)
		resp.Header.RCode = res.RCode
		resp.Answers = res.Answers
		resp.Authority = res.Authority
	}
	out := mustEncode(resp)
	if udpLimit > 0 && len(out) > udpLimit {
		// Too big for this transport: signal truncation, drop the
		// payload sections, and let the client retry over TCP.
		resp.Answers, resp.Authority, resp.Additional = nil, nil, nil
		resp.Header.TC = true
		out = mustEncode(resp)
	}
	return out
}

// mustEncode encodes a message the server itself constructed; any failure
// is a programming error surfaced as SERVFAIL with an empty body.
func mustEncode(m *dnswire.Message) []byte {
	out, err := m.Encode()
	if err != nil {
		fallback := &dnswire.Message{Header: dnswire.Header{
			ID: m.Header.ID, QR: true, RCode: dnswire.RCodeServFail,
		}}
		out, _ = fallback.Encode()
	}
	return out
}

// ListenUDP binds the UDP socket and returns the concrete address (useful
// with ":0").
func (s *Server) ListenUDP(addr string) (net.Addr, error) {
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.udp = conn
	s.mu.Unlock()
	return conn.LocalAddr(), nil
}

// ListenTCP binds the TCP socket and returns the concrete address.
func (s *Server) ListenTCP(addr string) (net.Addr, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.tcp = ln
	s.mu.Unlock()
	return ln.Addr(), nil
}

// ServeUDP answers datagrams until Close.
func (s *Server) ServeUDP() error {
	s.mu.Lock()
	conn := s.udp
	s.mu.Unlock()
	if conn == nil {
		return errors.New("server: ListenUDP not called")
	}
	buf := make([]byte, 4096)
	for {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			if s.closed() {
				return nil
			}
			return err
		}
		req := make([]byte, n)
		copy(req, buf[:n])
		go func(req []byte, from net.Addr) {
			if resp := s.HandleQuery(req, dnswire.MaxUDPPayload); resp != nil {
				if _, err := conn.WriteTo(resp, from); err != nil {
					s.logf("udp write to %s: %v", from, err)
				}
			}
		}(req, from)
	}
}

// ServeTCP accepts connections until Close. Each connection may carry
// multiple length-prefixed queries.
func (s *Server) ServeTCP() error {
	s.mu.Lock()
	ln := s.tcp
	s.mu.Unlock()
	if ln == nil {
		return errors.New("server: ListenTCP not called")
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			if s.closed() {
				return nil
			}
			return err
		}
		go s.serveConn(conn)
	}
}

func (s *Server) serveConn(conn net.Conn) {
	defer conn.Close()
	for {
		if err := conn.SetReadDeadline(time.Now().Add(tcpReadTimeout)); err != nil {
			return
		}
		var lenbuf [2]byte
		if _, err := io.ReadFull(conn, lenbuf[:]); err != nil {
			return // EOF or timeout: client is done
		}
		msglen := int(binary.BigEndian.Uint16(lenbuf[:]))
		req := make([]byte, msglen)
		if _, err := io.ReadFull(conn, req); err != nil {
			return
		}
		resp := s.HandleQuery(req, 0) // no truncation over TCP
		if resp == nil {
			return
		}
		var out [2]byte
		binary.BigEndian.PutUint16(out[:], uint16(len(resp)))
		if _, err := conn.Write(append(out[:], resp...)); err != nil {
			return
		}
	}
}

func (s *Server) closed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.done
}

// Close shuts both listeners down; Serve* then return nil.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.done = true
	var first error
	if s.udp != nil {
		first = s.udp.Close()
	}
	if s.tcp != nil {
		if err := s.tcp.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}
