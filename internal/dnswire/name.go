package dnswire

import (
	"errors"
	"strings"
)

// Domain names travel through hostwild as lowercase, dot-separated strings
// without a trailing dot ("" is the root). This file converts between that
// form and the RFC 1035 label sequence, including compression pointers on
// both encode and decode.

const (
	maxLabelLen = 63
	// maxNameWire is the RFC 1035 limit on the encoded form (255 octets).
	maxNameWire = 255
	// maxPointerHops bounds pointer chases so a malicious message with a
	// pointer loop cannot spin the decoder.
	maxPointerHops = 32
)

var (
	errNameTooLong    = errors.New("dnswire: name exceeds 255 octets")
	errLabelTooLong   = errors.New("dnswire: label exceeds 63 octets")
	errEmptyLabel     = errors.New("dnswire: empty label inside name")
	errTruncatedName  = errors.New("dnswire: truncated name")
	errPointerLoop    = errors.New("dnswire: compression pointer loop")
	errPointerForward = errors.New("dnswire: compression pointer does not point backward")
)

// CanonicalName lowercases a presentation-form name and strips a single
// trailing dot, producing hostwild's internal representation.
func CanonicalName(s string) string {
	s = strings.ToLower(strings.TrimSuffix(s, "."))
	return s
}

// splitLabels turns "a.b.c" into ["a","b","c"] and "" into nil (the root).
func splitLabels(name string) []string {
	if name == "" {
		return nil
	}
	return strings.Split(name, ".")
}

// builder accumulates an outgoing message and remembers where each name
// suffix landed so later occurrences compress to a 2-byte pointer.
type builder struct {
	buf []byte
	// offsets maps a canonical name suffix ("example.test") to the offset
	// of its first encoding. Pointers can only address offsets < 0x4000.
	offsets map[string]int
}

func newBuilder() *builder {
	return &builder{offsets: make(map[string]int)}
}

func (b *builder) uint8(v uint8)   { b.buf = append(b.buf, v) }
func (b *builder) uint16(v uint16) { b.buf = append(b.buf, byte(v>>8), byte(v)) }
func (b *builder) uint32(v uint32) {
	b.buf = append(b.buf, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}
func (b *builder) bytes(p []byte) { b.buf = append(b.buf, p...) }

// name encodes a canonical name, compressing against previously written
// suffixes per RFC 1035 §4.1.4.
func (b *builder) name(name string) error {
	labels := splitLabels(name)
	// Wire length check: each label costs len+1, plus the terminal zero.
	wire := 1
	for _, l := range labels {
		if l == "" {
			return errEmptyLabel
		}
		if len(l) > maxLabelLen {
			return errLabelTooLong
		}
		wire += len(l) + 1
	}
	if wire > maxNameWire {
		return errNameTooLong
	}
	for i := range labels {
		suffix := strings.Join(labels[i:], ".")
		if off, ok := b.offsets[suffix]; ok {
			b.uint16(0xC000 | uint16(off))
			return nil
		}
		if len(b.buf) < 0x4000 {
			b.offsets[suffix] = len(b.buf)
		}
		b.uint8(uint8(len(labels[i])))
		b.bytes([]byte(labels[i]))
	}
	b.uint8(0)
	return nil
}

// cursor walks an incoming message.
type cursor struct {
	buf []byte
	pos int
}

var errShortRead = errors.New("dnswire: message truncated")

func (c *cursor) uint8() (uint8, error) {
	if c.pos+1 > len(c.buf) {
		return 0, errShortRead
	}
	v := c.buf[c.pos]
	c.pos++
	return v, nil
}

func (c *cursor) uint16() (uint16, error) {
	if c.pos+2 > len(c.buf) {
		return 0, errShortRead
	}
	v := uint16(c.buf[c.pos])<<8 | uint16(c.buf[c.pos+1])
	c.pos += 2
	return v, nil
}

func (c *cursor) uint32() (uint32, error) {
	if c.pos+4 > len(c.buf) {
		return 0, errShortRead
	}
	v := uint32(c.buf[c.pos])<<24 | uint32(c.buf[c.pos+1])<<16 |
		uint32(c.buf[c.pos+2])<<8 | uint32(c.buf[c.pos+3])
	c.pos += 4
	return v, nil
}

func (c *cursor) bytes(n int) ([]byte, error) {
	if n < 0 || c.pos+n > len(c.buf) {
		return nil, errShortRead
	}
	v := c.buf[c.pos : c.pos+n]
	c.pos += n
	return v, nil
}

// name decodes a possibly-compressed name starting at the cursor. The
// cursor advances past the name's in-place bytes only (a pointer costs two
// bytes regardless of where it leads).
func (c *cursor) name() (string, error) {
	var labels []string
	pos := c.pos
	hops := 0
	jumped := false
	total := 0
	for {
		if pos >= len(c.buf) {
			return "", errTruncatedName
		}
		l := c.buf[pos]
		switch {
		case l == 0:
			if !jumped {
				c.pos = pos + 1
			}
			return strings.ToLower(strings.Join(labels, ".")), nil
		case l&0xC0 == 0xC0:
			if pos+2 > len(c.buf) {
				return "", errTruncatedName
			}
			target := int(l&0x3F)<<8 | int(c.buf[pos+1])
			// RFC 1035 compression only ever points at earlier data;
			// enforcing that plus a hop cap defeats loops.
			if target >= pos {
				return "", errPointerForward
			}
			if !jumped {
				c.pos = pos + 2
				jumped = true
			}
			hops++
			if hops > maxPointerHops {
				return "", errPointerLoop
			}
			pos = target
		case l&0xC0 != 0:
			return "", errors.New("dnswire: reserved label type")
		default:
			if pos+1+int(l) > len(c.buf) {
				return "", errTruncatedName
			}
			total += int(l) + 1
			if total > maxNameWire {
				return "", errNameTooLong
			}
			labels = append(labels, string(c.buf[pos+1:pos+1+int(l)]))
			pos += 1 + int(l)
		}
	}
}
