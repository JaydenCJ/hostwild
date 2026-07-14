package cli

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"time"

	"github.com/JaydenCJ/hostwild/internal/dnswire"
)

// runQuery is a minimal DNS client built on the same wire codec the
// server uses: it sends one question over UDP (or TCP with --tcp) and
// prints the decoded response. Handy for checking a hostwild instance
// without dig.
func runQuery(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("query", flag.ContinueOnError)
	var (
		serverAddr = fs.String("server", "127.0.0.1:5353", "DNS server address")
		qtype      = fs.String("type", "A", "question type: A, AAAA, TXT, NS, SOA, or ANY")
		useTCP     = fs.Bool("tcp", false, "query over TCP instead of UDP")
		timeout    = fs.Duration("timeout", 3*time.Second, "I/O timeout")
	)
	if !parseFlags(fs, args, stderr) {
		return ExitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "hostwild query: usage: query [flags] <fqdn>")
		return ExitUsage
	}
	t, ok := dnswire.ParseType(*qtype)
	if !ok {
		fmt.Fprintf(stderr, "hostwild query: unknown type %q\n", *qtype)
		return ExitUsage
	}

	id := uint16(rand.Intn(0x10000))
	req, err := dnswire.NewQuery(id, fs.Arg(0), t).Encode()
	if err != nil {
		fmt.Fprintf(stderr, "hostwild query: %v\n", err)
		return ExitRuntime
	}
	resp, err := exchange(*serverAddr, req, *useTCP, *timeout)
	if err != nil {
		fmt.Fprintf(stderr, "hostwild query: %v\n", err)
		return ExitRuntime
	}
	msg, err := dnswire.Decode(resp)
	if err != nil {
		fmt.Fprintf(stderr, "hostwild query: bad response: %v\n", err)
		return ExitRuntime
	}
	if msg.Header.ID != id {
		fmt.Fprintf(stderr, "hostwild query: response ID mismatch\n")
		return ExitRuntime
	}
	if msg.Header.TC && !*useTCP {
		fmt.Fprintln(stdout, ";; truncated — retry with --tcp")
	}
	return printResult(stdout, msg.Header.RCode, msg.Answers, msg.Authority)
}

// exchange performs one request/response round trip.
func exchange(addr string, req []byte, useTCP bool, timeout time.Duration) ([]byte, error) {
	network := "udp"
	if useTCP {
		network = "tcp"
	}
	conn, err := net.DialTimeout(network, addr, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	if useTCP {
		var pre [2]byte
		binary.BigEndian.PutUint16(pre[:], uint16(len(req)))
		if _, err := conn.Write(append(pre[:], req...)); err != nil {
			return nil, err
		}
		if _, err := io.ReadFull(conn, pre[:]); err != nil {
			return nil, err
		}
		resp := make([]byte, binary.BigEndian.Uint16(pre[:]))
		if _, err := io.ReadFull(conn, resp); err != nil {
			return nil, err
		}
		return resp, nil
	}
	if _, err := conn.Write(req); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}
