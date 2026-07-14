// Server tests: the pure HandleQuery byte transform (malformed input,
// non-queries, truncation) plus one loopback round trip per transport to
// prove the socket glue works end to end. Everything binds 127.0.0.1:0.
package server

import (
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/JaydenCJ/hostwild/internal/dnswire"
	"github.com/JaydenCJ/hostwild/internal/resolver"
	"github.com/JaydenCJ/hostwild/internal/zone"
)

const testZone = "dev.example.test"

func newServer(t *testing.T) *Server {
	t.Helper()
	store := zone.NewStore("")
	res := resolver.New(resolver.Config{Zone: testZone}, store)
	return &Server{Resolver: res}
}

func encodeQuery(t *testing.T, name string, qtype uint16) []byte {
	t.Helper()
	b, err := dnswire.NewQuery(0x4242, name, qtype).Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestHandleQueryAnswersMagicName(t *testing.T) {
	s := newServer(t)
	out := s.HandleQuery(encodeQuery(t, "10.0.0.7."+testZone, dnswire.TypeA), dnswire.MaxUDPPayload)
	msg, err := dnswire.Decode(out)
	if err != nil {
		t.Fatal(err)
	}
	if !msg.Header.QR || !msg.Header.AA || msg.Header.ID != 0x4242 {
		t.Fatalf("response header wrong: %+v", msg.Header)
	}
	if len(msg.Answers) != 1 || msg.Answers[0].Data.(dnswire.AData).Addr != netip.MustParseAddr("10.0.0.7") {
		t.Fatalf("answers wrong: %+v", msg.Answers)
	}
	// The question section must be echoed back.
	if len(msg.Questions) != 1 || msg.Questions[0].Name != "10.0.0.7."+testZone {
		t.Fatalf("question not echoed: %+v", msg.Questions)
	}
}

func TestHandleQueryEchoesRDBit(t *testing.T) {
	s := newServer(t)
	q := dnswire.NewQuery(1, "10.0.0.7."+testZone, dnswire.TypeA)
	q.Header.RD = true
	req, _ := q.Encode()
	msg, err := dnswire.Decode(s.HandleQuery(req, 0))
	if err != nil {
		t.Fatal(err)
	}
	if !msg.Header.RD || msg.Header.RA {
		t.Fatalf("RD/RA handling wrong: %+v", msg.Header)
	}
}

func TestHandleQueryMalformedGetsFormErrWithSameID(t *testing.T) {
	s := newServer(t)
	// A valid header claiming one question, followed by garbage.
	req := append(encodeQuery(t, "x."+testZone, dnswire.TypeA)[:12], 0xFF, 0xFF)
	out := s.HandleQuery(req, 0)
	msg, err := dnswire.Decode(out)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Header.RCode != dnswire.RCodeFormErr || msg.Header.ID != 0x4242 {
		t.Fatalf("want FORMERR echoing ID, got %+v", msg.Header)
	}
}

func TestHandleQueryDropsGarbageAndResponses(t *testing.T) {
	s := newServer(t)
	if out := s.HandleQuery([]byte{1, 2, 3}, 0); out != nil {
		t.Fatalf("short garbage got a %d-byte response", len(out))
	}
	// Answering answers enables spoofed-response reflection loops between
	// two DNS servers; QR=1 input must be dropped.
	q := dnswire.NewQuery(1, "10.0.0.7."+testZone, dnswire.TypeA)
	q.Header.QR = true
	req, _ := q.Encode()
	if out := s.HandleQuery(req, 0); out != nil {
		t.Fatal("server answered a response packet")
	}
}

func TestHandleQueryNonQueryOpcodeIsNotImp(t *testing.T) {
	s := newServer(t)
	q := dnswire.NewQuery(1, "x."+testZone, dnswire.TypeA)
	q.Header.Opcode = 5 // UPDATE
	req, _ := q.Encode()
	msg, err := dnswire.Decode(s.HandleQuery(req, 0))
	if err != nil {
		t.Fatal(err)
	}
	if msg.Header.RCode != dnswire.RCodeNotImp {
		t.Fatalf("rcode %s, want NOTIMP", dnswire.RCodeName(msg.Header.RCode))
	}
}

func TestHandleQuerySetsTCWhenOverUDPLimit(t *testing.T) {
	s := newServer(t)
	// TXT answers for a long name; force truncation with a tiny limit.
	store := zone.NewStore("")
	if err := store.Set("big", zone.Record{Type: dnswire.TypeTXT, TXT: []string{strings.Repeat("a", 200)}}); err != nil {
		t.Fatal(err)
	}
	s.Resolver = resolver.New(resolver.Config{Zone: testZone}, store)
	req := encodeQuery(t, "big."+testZone, dnswire.TypeTXT)
	msg, err := dnswire.Decode(s.HandleQuery(req, 100))
	if err != nil {
		t.Fatal(err)
	}
	if !msg.Header.TC || len(msg.Answers) != 0 {
		t.Fatalf("truncation not signalled: TC=%v answers=%d", msg.Header.TC, len(msg.Answers))
	}
	// The same query over TCP (limit 0) returns the full answer.
	full, err := dnswire.Decode(s.HandleQuery(req, 0))
	if err != nil {
		t.Fatal(err)
	}
	if full.Header.TC || len(full.Answers) != 1 {
		t.Fatalf("TCP path wrong: TC=%v answers=%d", full.Header.TC, len(full.Answers))
	}
}

func TestUDPLoopbackRoundTrip(t *testing.T) {
	s := newServer(t)
	addr, err := s.ListenUDP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go func() { _ = s.ServeUDP() }()

	conn, err := net.Dial("udp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(encodeQuery(t, "app-192-168-1-9."+testZone, dnswire.TypeA)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := dnswire.Decode(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	if len(msg.Answers) != 1 || msg.Answers[0].Data.(dnswire.AData).Addr != netip.MustParseAddr("192.168.1.9") {
		t.Fatalf("UDP answer wrong: %+v", msg.Answers)
	}
}

func TestTCPLoopbackRoundTripWithFraming(t *testing.T) {
	s := newServer(t)
	addr, err := s.ListenTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go func() { _ = s.ServeTCP() }()

	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	req := encodeQuery(t, "10.0.0.7."+testZone, dnswire.TypeA)
	framed := append([]byte{byte(len(req) >> 8), byte(len(req))}, req...)
	if _, err := conn.Write(framed); err != nil {
		t.Fatal(err)
	}
	pre := make([]byte, 2)
	if _, err := io.ReadFull(conn, pre); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, int(pre[0])<<8|int(pre[1]))
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatal(err)
	}
	msg, err := dnswire.Decode(resp)
	if err != nil {
		t.Fatal(err)
	}
	if len(msg.Answers) != 1 || msg.Answers[0].Data.(dnswire.AData).Addr != netip.MustParseAddr("10.0.0.7") {
		t.Fatalf("TCP answer wrong: %+v", msg.Answers)
	}
}
