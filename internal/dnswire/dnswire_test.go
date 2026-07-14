// Wire-format tests: every byte the codec produces or consumes is checked
// against hand-computed RFC 1035 encodings, and hostile inputs (pointer
// loops, truncation, oversized labels) must fail loudly instead of
// corrupting or spinning.
package dnswire

import (
	"bytes"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func mustEncodeMsg(t *testing.T, m *Message) []byte {
	t.Helper()
	b, err := m.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	return b
}

func TestHeaderFlagsRoundTrip(t *testing.T) {
	h := Header{ID: 0xBEEF, QR: true, Opcode: 2, AA: true, TC: true, RD: true, RA: true, RCode: RCodeRefused}
	if got := headerFromFlags(h.ID, h.flags()); got != h {
		t.Fatalf("all-bits round trip mismatch: %+v != %+v", got, h)
	}
	z := headerFromFlags(1, 0)
	if z.QR || z.AA || z.TC || z.RD || z.RA || z.Opcode != 0 || z.RCode != 0 {
		t.Fatalf("zero flags decoded dirty: %+v", z)
	}
}

func TestNameEncodingMatchesRFC1035Bytes(t *testing.T) {
	b := newBuilder()
	if err := b.name("app.example.test"); err != nil {
		t.Fatal(err)
	}
	want := []byte("\x03app\x07example\x04test\x00")
	if !bytes.Equal(b.buf, want) {
		t.Fatalf("wire bytes %q, want %q", b.buf, want)
	}
}

func TestRootNameEncodesToSingleZeroByte(t *testing.T) {
	b := newBuilder()
	if err := b.name(""); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b.buf, []byte{0}) {
		t.Fatalf("root encoded as %v, want [0]", b.buf)
	}
}

func TestNameCompressionEmitsPointerForRepeatedSuffix(t *testing.T) {
	b := newBuilder()
	if err := b.name("app.example.test"); err != nil {
		t.Fatal(err)
	}
	before := len(b.buf)
	if err := b.name("db.example.test"); err != nil {
		t.Fatal(err)
	}
	// Second name should cost: 1+2 ("db") + 2 (pointer) = 5 bytes.
	if got := len(b.buf) - before; got != 5 {
		t.Fatalf("compressed name cost %d bytes, want 5", got)
	}
	// The pointer must target offset 4, where "example.test" begins.
	tail := b.buf[len(b.buf)-2:]
	if tail[0] != 0xC0 || tail[1] != 4 {
		t.Fatalf("pointer bytes % x, want c0 04", tail)
	}
}

func TestCompressedNameDecodesBack(t *testing.T) {
	b := newBuilder()
	for _, n := range []string{"app.example.test", "db.example.test", "example.test"} {
		if err := b.name(n); err != nil {
			t.Fatal(err)
		}
	}
	c := &cursor{buf: b.buf}
	for _, want := range []string{"app.example.test", "db.example.test", "example.test"} {
		got, err := c.name()
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("decoded %q, want %q", got, want)
		}
	}
}

func TestNameDecodeUppercaseIsLowered(t *testing.T) {
	c := &cursor{buf: []byte("\x03ApP\x04TeSt\x00")}
	got, err := c.name()
	if err != nil {
		t.Fatal(err)
	}
	if got != "app.test" {
		t.Fatalf("got %q, want lowercased app.test", got)
	}
}

func TestNameEncodeEnforcesRFCLimits(t *testing.T) {
	long := strings.Repeat("a", 63)
	cases := []struct {
		name string
		want error
	}{
		{strings.Repeat("a", 64) + ".test", errLabelTooLong},
		{strings.Join([]string{long, long, long, long, "x"}, "."), errNameTooLong},
		{"a..b", errEmptyLabel},
	}
	for _, c := range cases {
		if err := newBuilder().name(c.name); !errors.Is(err, c.want) {
			t.Errorf("name(%.20q...): got %v, want %v", c.name, err, c.want)
		}
	}
}

func TestNameDecodeRejectsHostileInput(t *testing.T) {
	// Pointer at offset 0 targeting offset 4 (>= its own position):
	// legal compression only ever points backward.
	c := &cursor{buf: []byte{0xC0, 0x04, 0x00, 0x00, 0x03, 'a', 'b', 'c', 0x00}}
	if _, err := c.name(); !errors.Is(err, errPointerForward) {
		t.Fatalf("forward pointer: got %v, want errPointerForward", err)
	}
	// Two pointers that chase each other; backward-only rule plus the hop
	// cap must terminate the decode with an error, not an infinite loop.
	c = &cursor{buf: []byte{0x00, 0xC0, 0x03, 0xC0, 0x01}, pos: 3}
	if _, err := c.name(); err == nil {
		t.Fatal("pointer loop decoded without error")
	}
	// Label runs past the end of the message.
	c = &cursor{buf: []byte{0x05, 'a', 'b'}}
	if _, err := c.name(); !errors.Is(err, errTruncatedName) {
		t.Fatalf("truncated: got %v, want errTruncatedName", err)
	}
}

func TestQueryMessageRoundTrip(t *testing.T) {
	m := NewQuery(0x1234, "App.Dev.Example.Test.", TypeA)
	decoded, err := Decode(mustEncodeMsg(t, m))
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Header.ID != 0x1234 || !decoded.Header.RD {
		t.Fatalf("header mangled: %+v", decoded.Header)
	}
	q := decoded.Questions[0]
	if q.Name != "app.dev.example.test" || q.Type != TypeA || q.Class != ClassINET {
		t.Fatalf("question mangled: %+v", q)
	}
}

func TestARecordRoundTrip(t *testing.T) {
	m := &Message{
		Header: Header{ID: 7, QR: true, AA: true},
		Answers: []RR{{
			Name: "x.example.test", Type: TypeA, Class: ClassINET, TTL: 60,
			Data: AData{Addr: netip.MustParseAddr("192.0.2.1")},
		}},
	}
	decoded, err := Decode(mustEncodeMsg(t, m))
	if err != nil {
		t.Fatal(err)
	}
	got := decoded.Answers[0]
	if got.Data.(AData).Addr != netip.MustParseAddr("192.0.2.1") || got.TTL != 60 {
		t.Fatalf("A record mangled: %+v", got)
	}
}

func TestAAAARecordRoundTrip(t *testing.T) {
	addr := netip.MustParseAddr("2001:db8::7")
	m := &Message{Answers: []RR{{
		Name: "x.example.test", Type: TypeAAAA, Class: ClassINET, TTL: 30,
		Data: AAAAData{Addr: addr},
	}}}
	decoded, err := Decode(mustEncodeMsg(t, m))
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Answers[0].Data.(AAAAData).Addr != addr {
		t.Fatalf("AAAA mangled: %+v", decoded.Answers[0])
	}
}

func TestTXTRecordRoundTripMultipleStrings(t *testing.T) {
	m := &Message{Answers: []RR{{
		Name: "_acme-challenge.example.test", Type: TypeTXT, Class: ClassINET, TTL: 30,
		Data: TXTData{Strings: []string{"first", "second-string"}},
	}}}
	decoded, err := Decode(mustEncodeMsg(t, m))
	if err != nil {
		t.Fatal(err)
	}
	got := decoded.Answers[0].Data.(TXTData).Strings
	if len(got) != 2 || got[0] != "first" || got[1] != "second-string" {
		t.Fatalf("TXT strings mangled: %v", got)
	}
}

func TestSOARecordRoundTripWithCompressedNames(t *testing.T) {
	soa := SOAData{
		MName: "ns.example.test", RName: "hostmaster.example.test",
		Serial: 42, Refresh: 7200, Retry: 900, Expire: 1209600, Minimum: 60,
	}
	m := &Message{
		Questions: []Question{{Name: "example.test", Type: TypeSOA, Class: ClassINET}},
		Answers: []RR{{
			Name: "example.test", Type: TypeSOA, Class: ClassINET, TTL: 60, Data: soa,
		}},
	}
	decoded, err := Decode(mustEncodeMsg(t, m))
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Answers[0].Data.(SOAData) != soa {
		t.Fatalf("SOA mangled: %+v", decoded.Answers[0].Data)
	}
}

func TestNSRecordRoundTrip(t *testing.T) {
	m := &Message{Answers: []RR{{
		Name: "example.test", Type: TypeNS, Class: ClassINET, TTL: 60,
		Data: NSData{Host: "ns.example.test"},
	}}}
	decoded, err := Decode(mustEncodeMsg(t, m))
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Answers[0].Data.(NSData).Host != "ns.example.test" {
		t.Fatalf("NS mangled: %+v", decoded.Answers[0].Data)
	}
}

func TestUnknownRTypeSurvivesAsRawData(t *testing.T) {
	m := &Message{Answers: []RR{{
		Name: "x.example.test", Type: 99, Class: ClassINET, TTL: 60,
		Data: RawData{Data: []byte{1, 2, 3}},
	}}}
	decoded, err := Decode(mustEncodeMsg(t, m))
	if err != nil {
		t.Fatal(err)
	}
	raw := decoded.Answers[0].Data.(RawData)
	if !bytes.Equal(raw.Data, []byte{1, 2, 3}) {
		t.Fatalf("raw rdata mangled: %v", raw.Data)
	}
}

func TestDecodeRejectsMalformedMessages(t *testing.T) {
	if _, err := Decode([]byte{1, 2, 3}); err == nil {
		t.Error("short header decoded without error")
	}
	// Header claims one question but no bytes follow.
	if _, err := Decode([]byte{0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err == nil {
		t.Error("lying QDCOUNT decoded without error")
	}
	// An A record whose RDLENGTH is 3: encode as type 99 raw, then rewrite
	// the type to A so the size check must fire.
	m := &Message{Answers: []RR{{
		Name: "x.test", Type: 99, Class: ClassINET, TTL: 1,
		Data: RawData{Data: []byte{1, 2, 3}},
	}}}
	buf := mustEncodeMsg(t, m)
	i := bytes.Index(buf, []byte{0x00, 99})
	buf[i+1] = byte(TypeA)
	if _, err := Decode(buf); err == nil {
		t.Error("3-byte A rdata decoded without error")
	}
}

func TestEncodeRejectsInvalidRData(t *testing.T) {
	bad := []RData{
		TXTData{Strings: []string{strings.Repeat("a", 256)}}, // > 255 octets
		AAAAData{Addr: netip.MustParseAddr("192.0.2.1")},     // v4 in AAAA
		AData{Addr: netip.MustParseAddr("2001:db8::1")},      // v6 in A
		TXTData{}, // empty TXT
	}
	for i, d := range bad {
		m := &Message{Answers: []RR{{Name: "x.test", Type: TypeTXT, Class: ClassINET, TTL: 1, Data: d}}}
		if _, err := m.Encode(); err == nil {
			t.Errorf("case %d (%T) encoded without error", i, d)
		}
	}
}

func TestCanonicalName(t *testing.T) {
	for in, want := range map[string]string{
		"App.Example.Test.": "app.example.test",
		"already.lower":     "already.lower",
		".":                 "",
		"":                  "",
	} {
		if got := CanonicalName(in); got != want {
			t.Errorf("CanonicalName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPresentationHelpers(t *testing.T) {
	for _, typ := range []uint16{TypeA, TypeNS, TypeCNAME, TypeSOA, TypeTXT, TypeAAAA, TypeANY} {
		name := TypeName(typ)
		back, ok := ParseType(name)
		if !ok || back != typ {
			t.Errorf("ParseType(TypeName(%d)) = %d, %v", typ, back, ok)
		}
	}
	if _, ok := ParseType("BOGUS"); ok {
		t.Error("ParseType accepted BOGUS")
	}
	if got := TypeName(99); got != "TYPE99" {
		t.Errorf("TypeName(99) = %q", got)
	}
	if RCodeName(RCodeNXDomain) != "NXDOMAIN" || RCodeName(15) != "RCODE15" {
		t.Errorf("RCodeName mapping broken: %q %q", RCodeName(RCodeNXDomain), RCodeName(15))
	}
	rr := RR{Name: "x.example.test", Type: TypeA, Class: ClassINET, TTL: 60,
		Data: AData{Addr: netip.MustParseAddr("10.0.0.7")}}
	if want := "x.example.test.\t60\tIN\tA\t10.0.0.7"; rr.String() != want {
		t.Errorf("String() = %q, want %q", rr.String(), want)
	}
}
