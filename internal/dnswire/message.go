package dnswire

import (
	"errors"
	"fmt"
)

// Header is the fixed 12-byte DNS message header with its flag word
// unpacked into named fields.
type Header struct {
	ID     uint16
	QR     bool  // response flag
	Opcode uint8 // 4 bits
	AA     bool  // authoritative answer
	TC     bool  // truncated
	RD     bool  // recursion desired (echoed from the query)
	RA     bool  // recursion available (hostwild never recurses)
	RCode  uint8 // 4 bits
}

// flags packs the header flag word.
func (h Header) flags() uint16 {
	var f uint16
	if h.QR {
		f |= 1 << 15
	}
	f |= uint16(h.Opcode&0x0F) << 11
	if h.AA {
		f |= 1 << 10
	}
	if h.TC {
		f |= 1 << 9
	}
	if h.RD {
		f |= 1 << 8
	}
	if h.RA {
		f |= 1 << 7
	}
	f |= uint16(h.RCode & 0x0F)
	return f
}

// headerFromFlags unpacks a flag word into a Header (ID set separately).
func headerFromFlags(id, f uint16) Header {
	return Header{
		ID:     id,
		QR:     f&(1<<15) != 0,
		Opcode: uint8(f >> 11 & 0x0F),
		AA:     f&(1<<10) != 0,
		TC:     f&(1<<9) != 0,
		RD:     f&(1<<8) != 0,
		RA:     f&(1<<7) != 0,
		RCode:  uint8(f & 0x0F),
	}
}

// Question is a single query tuple.
type Question struct {
	Name  string // canonical: lowercase, no trailing dot
	Type  uint16
	Class uint16
}

// RR is a decoded or to-be-encoded resource record.
type RR struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	Data  RData
}

// String renders one record in zone-file-ish presentation form.
func (r RR) String() string {
	return fmt.Sprintf("%s.\t%d\tIN\t%s\t%s", r.Name, r.TTL, TypeName(r.Type), r.Data.String())
}

// Message is a full DNS message.
type Message struct {
	Header     Header
	Questions  []Question
	Answers    []RR
	Authority  []RR
	Additional []RR
}

var errCountOverflow = errors.New("dnswire: section exceeds 65535 records")

// Encode serializes the message with name compression. Section counts are
// derived from the slices, never trusted from the Header.
func (m *Message) Encode() ([]byte, error) {
	for _, n := range []int{len(m.Questions), len(m.Answers), len(m.Authority), len(m.Additional)} {
		if n > 0xFFFF {
			return nil, errCountOverflow
		}
	}
	b := newBuilder()
	b.uint16(m.Header.ID)
	b.uint16(m.Header.flags())
	b.uint16(uint16(len(m.Questions)))
	b.uint16(uint16(len(m.Answers)))
	b.uint16(uint16(len(m.Authority)))
	b.uint16(uint16(len(m.Additional)))
	for _, q := range m.Questions {
		if err := b.name(q.Name); err != nil {
			return nil, err
		}
		b.uint16(q.Type)
		b.uint16(q.Class)
	}
	for _, sec := range [][]RR{m.Answers, m.Authority, m.Additional} {
		for _, rr := range sec {
			if err := encodeRR(b, rr); err != nil {
				return nil, err
			}
		}
	}
	return b.buf, nil
}

func encodeRR(b *builder, rr RR) error {
	if rr.Data == nil {
		return errors.New("dnswire: record has no data")
	}
	if err := b.name(rr.Name); err != nil {
		return err
	}
	b.uint16(rr.Type)
	b.uint16(rr.Class)
	b.uint32(rr.TTL)
	// Reserve the RDLENGTH slot, write RDATA, then patch the length.
	lenAt := len(b.buf)
	b.uint16(0)
	start := len(b.buf)
	if err := rr.Data.appendTo(b); err != nil {
		return err
	}
	rdlen := len(b.buf) - start
	if rdlen > 0xFFFF {
		return errors.New("dnswire: rdata exceeds 65535 octets")
	}
	b.buf[lenAt] = byte(rdlen >> 8)
	b.buf[lenAt+1] = byte(rdlen)
	return nil
}

// Decode parses a complete DNS message.
func Decode(buf []byte) (*Message, error) {
	c := &cursor{buf: buf}
	id, err := c.uint16()
	if err != nil {
		return nil, err
	}
	flags, err := c.uint16()
	if err != nil {
		return nil, err
	}
	var counts [4]uint16
	for i := range counts {
		if counts[i], err = c.uint16(); err != nil {
			return nil, err
		}
	}
	m := &Message{Header: headerFromFlags(id, flags)}
	for i := 0; i < int(counts[0]); i++ {
		var q Question
		if q.Name, err = c.name(); err != nil {
			return nil, err
		}
		if q.Type, err = c.uint16(); err != nil {
			return nil, err
		}
		if q.Class, err = c.uint16(); err != nil {
			return nil, err
		}
		m.Questions = append(m.Questions, q)
	}
	for sec, dst := range []*[]RR{&m.Answers, &m.Authority, &m.Additional} {
		for i := 0; i < int(counts[sec+1]); i++ {
			rr, err := decodeRR(c)
			if err != nil {
				return nil, err
			}
			*dst = append(*dst, rr)
		}
	}
	return m, nil
}

func decodeRR(c *cursor) (RR, error) {
	var rr RR
	var err error
	if rr.Name, err = c.name(); err != nil {
		return rr, err
	}
	if rr.Type, err = c.uint16(); err != nil {
		return rr, err
	}
	if rr.Class, err = c.uint16(); err != nil {
		return rr, err
	}
	if rr.TTL, err = c.uint32(); err != nil {
		return rr, err
	}
	rdlen, err := c.uint16()
	if err != nil {
		return rr, err
	}
	base := c.pos
	rdata, err := c.bytes(int(rdlen))
	if err != nil {
		return rr, err
	}
	if rr.Data, err = decodeRData(rr.Type, rdata, c.buf, base); err != nil {
		return rr, err
	}
	return rr, nil
}

// NewQuery builds a canonical single-question query message.
func NewQuery(id uint16, name string, qtype uint16) *Message {
	return &Message{
		Header:    Header{ID: id, RD: true, Opcode: OpcodeQuery},
		Questions: []Question{{Name: CanonicalName(name), Type: qtype, Class: ClassINET}},
	}
}
