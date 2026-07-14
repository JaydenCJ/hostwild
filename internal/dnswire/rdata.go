package dnswire

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// RData is the typed payload of a resource record. Each concrete type
// knows how to append its wire form to a builder and render itself for
// humans; decoding lives in decodeRData so unknown types degrade to
// RawData instead of failing the whole message.
type RData interface {
	// appendTo writes the RDATA bytes (without the length prefix).
	appendTo(b *builder) error
	// String renders the presentation form, e.g. "192.0.2.1".
	String() string
}

// AData is an IPv4 address record (type A).
type AData struct{ Addr netip.Addr }

func (d AData) appendTo(b *builder) error {
	if !d.Addr.Is4() {
		return errors.New("dnswire: A record requires an IPv4 address")
	}
	a4 := d.Addr.As4()
	b.bytes(a4[:])
	return nil
}
func (d AData) String() string { return d.Addr.String() }

// AAAAData is an IPv6 address record (type AAAA).
type AAAAData struct{ Addr netip.Addr }

func (d AAAAData) appendTo(b *builder) error {
	if !d.Addr.Is6() || d.Addr.Is4In6() {
		return errors.New("dnswire: AAAA record requires an IPv6 address")
	}
	a16 := d.Addr.As16()
	b.bytes(a16[:])
	return nil
}
func (d AAAAData) String() string { return d.Addr.String() }

// TXTData carries one or more character strings (type TXT).
type TXTData struct{ Strings []string }

func (d TXTData) appendTo(b *builder) error {
	if len(d.Strings) == 0 {
		return errors.New("dnswire: TXT record requires at least one string")
	}
	for _, s := range d.Strings {
		if len(s) > 255 {
			return errors.New("dnswire: TXT string exceeds 255 octets")
		}
		b.uint8(uint8(len(s)))
		b.bytes([]byte(s))
	}
	return nil
}
func (d TXTData) String() string {
	quoted := make([]string, len(d.Strings))
	for i, s := range d.Strings {
		quoted[i] = fmt.Sprintf("%q", s)
	}
	return strings.Join(quoted, " ")
}

// NSData names an authoritative server (type NS).
type NSData struct{ Host string }

func (d NSData) appendTo(b *builder) error { return b.name(d.Host) }
func (d NSData) String() string            { return d.Host + "." }

// CNAMEData aliases one name to another (type CNAME).
type CNAMEData struct{ Target string }

func (d CNAMEData) appendTo(b *builder) error { return b.name(d.Target) }
func (d CNAMEData) String() string            { return d.Target + "." }

// SOAData is the start-of-authority record (type SOA).
type SOAData struct {
	MName   string // primary name server
	RName   string // responsible mailbox, dot-encoded
	Serial  uint32
	Refresh uint32
	Retry   uint32
	Expire  uint32
	Minimum uint32 // negative-caching TTL
}

func (d SOAData) appendTo(b *builder) error {
	if err := b.name(d.MName); err != nil {
		return err
	}
	if err := b.name(d.RName); err != nil {
		return err
	}
	b.uint32(d.Serial)
	b.uint32(d.Refresh)
	b.uint32(d.Retry)
	b.uint32(d.Expire)
	b.uint32(d.Minimum)
	return nil
}
func (d SOAData) String() string {
	return fmt.Sprintf("%s. %s. %d %d %d %d %d",
		d.MName, d.RName, d.Serial, d.Refresh, d.Retry, d.Expire, d.Minimum)
}

// RawData preserves the RDATA of record types hostwild does not model, so
// decoded messages remain lossless.
type RawData struct{ Data []byte }

func (d RawData) appendTo(b *builder) error { b.bytes(d.Data); return nil }
func (d RawData) String() string            { return fmt.Sprintf("\\# %d", len(d.Data)) }

// decodeRData parses the RDATA section of one record. rdata is the exact
// slice for this record; whole is the full message for compressed names
// inside NS/CNAME/SOA, with base the absolute offset where rdata begins.
func decodeRData(typ uint16, rdata []byte, whole []byte, base int) (RData, error) {
	switch typ {
	case TypeA:
		if len(rdata) != 4 {
			return nil, fmt.Errorf("dnswire: A rdata is %d bytes, want 4", len(rdata))
		}
		return AData{Addr: netip.AddrFrom4([4]byte(rdata))}, nil
	case TypeAAAA:
		if len(rdata) != 16 {
			return nil, fmt.Errorf("dnswire: AAAA rdata is %d bytes, want 16", len(rdata))
		}
		return AAAAData{Addr: netip.AddrFrom16([16]byte(rdata))}, nil
	case TypeTXT:
		var ss []string
		for i := 0; i < len(rdata); {
			l := int(rdata[i])
			if i+1+l > len(rdata) {
				return nil, errors.New("dnswire: truncated TXT string")
			}
			ss = append(ss, string(rdata[i+1:i+1+l]))
			i += 1 + l
		}
		if len(ss) == 0 {
			return nil, errors.New("dnswire: empty TXT rdata")
		}
		return TXTData{Strings: ss}, nil
	case TypeNS, TypeCNAME:
		c := &cursor{buf: whole, pos: base}
		n, err := c.name()
		if err != nil {
			return nil, err
		}
		if typ == TypeNS {
			return NSData{Host: n}, nil
		}
		return CNAMEData{Target: n}, nil
	case TypeSOA:
		c := &cursor{buf: whole, pos: base}
		mname, err := c.name()
		if err != nil {
			return nil, err
		}
		rname, err := c.name()
		if err != nil {
			return nil, err
		}
		var vals [5]uint32
		for i := range vals {
			if vals[i], err = c.uint32(); err != nil {
				return nil, err
			}
		}
		return SOAData{
			MName: mname, RName: rname,
			Serial: vals[0], Refresh: vals[1], Retry: vals[2],
			Expire: vals[3], Minimum: vals[4],
		}, nil
	default:
		return RawData{Data: append([]byte(nil), rdata...)}, nil
	}
}
