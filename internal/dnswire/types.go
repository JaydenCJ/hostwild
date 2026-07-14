// Package dnswire implements the DNS wire format (RFC 1035) from scratch:
// header packing, domain-name encoding with message compression, and the
// record types hostwild serves. It is a pure codec — no I/O, no globals —
// so every byte it produces or consumes is unit-testable.
package dnswire

import "fmt"

// Record types hostwild understands. Unknown types survive a decode as
// RawData so a message can be re-examined without loss.
const (
	TypeA     uint16 = 1
	TypeNS    uint16 = 2
	TypeCNAME uint16 = 5
	TypeSOA   uint16 = 6
	TypeTXT   uint16 = 16
	TypeAAAA  uint16 = 28
	TypeOPT   uint16 = 41
	TypeANY   uint16 = 255
)

// ClassINET is the only class hostwild serves.
const ClassINET uint16 = 1

// Response codes (RCODE).
const (
	RCodeNoError  uint8 = 0
	RCodeFormErr  uint8 = 1
	RCodeServFail uint8 = 2
	RCodeNXDomain uint8 = 3
	RCodeNotImp   uint8 = 4
	RCodeRefused  uint8 = 5
)

// OpcodeQuery is the only opcode hostwild answers; everything else gets
// NOTIMP.
const OpcodeQuery uint8 = 0

// MaxUDPPayload is the classic RFC 1035 limit for UDP responses. Larger
// responses are truncated (TC=1) so the client retries over TCP.
const MaxUDPPayload = 512

// typeNames maps record types to their presentation names for CLI output.
var typeNames = map[uint16]string{
	TypeA:     "A",
	TypeNS:    "NS",
	TypeCNAME: "CNAME",
	TypeSOA:   "SOA",
	TypeTXT:   "TXT",
	TypeAAAA:  "AAAA",
	TypeOPT:   "OPT",
	TypeANY:   "ANY",
}

// TypeName renders a record type for humans, e.g. "A" or "TYPE99".
func TypeName(t uint16) string {
	if n, ok := typeNames[t]; ok {
		return n
	}
	return fmt.Sprintf("TYPE%d", t)
}

// ParseType maps a presentation name back to a type code.
func ParseType(s string) (uint16, bool) {
	for t, n := range typeNames {
		if n == s {
			return t, true
		}
	}
	return 0, false
}

// rcodeNames maps response codes to their presentation names.
var rcodeNames = map[uint8]string{
	RCodeNoError:  "NOERROR",
	RCodeFormErr:  "FORMERR",
	RCodeServFail: "SERVFAIL",
	RCodeNXDomain: "NXDOMAIN",
	RCodeNotImp:   "NOTIMP",
	RCodeRefused:  "REFUSED",
}

// RCodeName renders a response code for humans, e.g. "NXDOMAIN".
func RCodeName(rc uint8) string {
	if n, ok := rcodeNames[rc]; ok {
		return n
	}
	return fmt.Sprintf("RCODE%d", rc)
}
