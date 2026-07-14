// Package magic extracts IP addresses embedded in hostnames, the trick
// popularized by nip.io and sslip.io: `app.10.0.0.7.dev.example.test`
// answers 10.0.0.7 without any registration. hostwild supports four
// notations — dotted and dashed IPv4, 8-hex-digit IPv4, and dashed IPv6 —
// each with an optional `name.` or `name-` prefix.
package magic

import (
	"net/netip"
	"strconv"
	"strings"
)

// Extract inspects the labels to the left of the zone (leftmost first) and
// returns the embedded address, if any. Matching prefers the most specific
// notation and always anchors at the right edge, so a prefix like
// `app.10.0.0.7` or `db-192-168-1-9` resolves to the trailing address.
//
// Supported notations, tried in order:
//
//  1. dotted IPv4 across the last four labels:  10.0.0.7
//  2. dashed IPv6 as the whole last label:      2a01-4f8--1  (dash for
//     colon, so `--` encodes `::`)
//  3. dashed IPv4 inside the last label:        10-0-0-7, app-10-0-0-7
//  4. hexadecimal IPv4 as the last dash-part:   0a000007, app-0a000007
//
// IPv6 is checked before dashed IPv4 so an eight-group address like
// `2001-db8-0-0-0-0-0-42` is read whole, not as `0.0.0.42`.
func Extract(labels []string) (netip.Addr, bool) {
	if len(labels) == 0 {
		return netip.Addr{}, false
	}
	if a, ok := dottedIPv4(labels); ok {
		return a, true
	}
	last := labels[len(labels)-1]
	if a, ok := dashedIPv6(last); ok {
		return a, true
	}
	if a, ok := dashedIPv4(last); ok {
		return a, true
	}
	if a, ok := hexIPv4(last); ok {
		return a, true
	}
	return netip.Addr{}, false
}

// octet parses a strict decimal IPv4 octet: no signs, no leading zeros
// (except "0" itself), value 0-255. Rejecting "01" avoids ambiguity with
// version-like prefixes such as `v1.01.2.3.4`.
func octet(s string) (byte, bool) {
	if s == "" || len(s) > 3 {
		return 0, false
	}
	if len(s) > 1 && s[0] == '0' {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(s)
	if err != nil || n > 255 {
		return 0, false
	}
	return byte(n), true
}

// dottedIPv4 matches when the last four labels are each a decimal octet.
func dottedIPv4(labels []string) (netip.Addr, bool) {
	if len(labels) < 4 {
		return netip.Addr{}, false
	}
	var b [4]byte
	for i := 0; i < 4; i++ {
		o, ok := octet(labels[len(labels)-4+i])
		if !ok {
			return netip.Addr{}, false
		}
		b[i] = o
	}
	return netip.AddrFrom4(b), true
}

// dashedIPv4 matches when the last four dash-separated parts of a label
// are decimal octets, e.g. "10-0-0-7" or "app-10-0-0-7".
func dashedIPv4(label string) (netip.Addr, bool) {
	parts := strings.Split(label, "-")
	if len(parts) < 4 {
		return netip.Addr{}, false
	}
	var b [4]byte
	for i := 0; i < 4; i++ {
		o, ok := octet(parts[len(parts)-4+i])
		if !ok {
			return netip.Addr{}, false
		}
		b[i] = o
	}
	return netip.AddrFrom4(b), true
}

// hexIPv4 matches when the last dash-separated part of a label is exactly
// eight lowercase hex digits, e.g. "0a000007" or "app-0a000007".
func hexIPv4(label string) (netip.Addr, bool) {
	part := label
	if i := strings.LastIndexByte(label, '-'); i >= 0 {
		part = label[i+1:]
	}
	if len(part) != 8 {
		return netip.Addr{}, false
	}
	var b [4]byte
	for i := 0; i < 8; i += 2 {
		hi, ok1 := hexNibble(part[i])
		lo, ok2 := hexNibble(part[i+1])
		if !ok1 || !ok2 {
			return netip.Addr{}, false
		}
		b[i/2] = hi<<4 | lo
	}
	return netip.AddrFrom4(b), true
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	default:
		return 0, false
	}
}

// dashedIPv6 matches when substituting ':' for '-' across the whole label
// yields a valid IPv6 address, e.g. "--1" → "::1", "2a01-4f8--1" →
// "2a01:4f8::1". The label must contain a dash so bare words never match,
// and the result must be a genuine IPv6 address (not IPv4-mapped text).
func dashedIPv6(label string) (netip.Addr, bool) {
	if !strings.Contains(label, "-") {
		return netip.Addr{}, false
	}
	cand := strings.ReplaceAll(label, "-", ":")
	a, err := netip.ParseAddr(cand)
	if err != nil || !a.Is6() || a.Is4In6() {
		return netip.Addr{}, false
	}
	return a, true
}
