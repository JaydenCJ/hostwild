// Magic-hostname tests: each supported notation, its prefix forms, and —
// just as important — the near-misses that must NOT resolve, since a
// false positive here would hijack a name a user meant to register.
package magic

import (
	"net/netip"
	"strings"
	"testing"
)

// extract is a test helper taking the dotted relative name.
func extract(t *testing.T, rel string) (netip.Addr, bool) {
	t.Helper()
	return Extract(strings.Split(rel, "."))
}

func wantAddr(t *testing.T, rel, want string) {
	t.Helper()
	got, ok := extract(t, rel)
	if !ok {
		t.Errorf("Extract(%q) found nothing, want %s", rel, want)
		return
	}
	if got != netip.MustParseAddr(want) {
		t.Errorf("Extract(%q) = %s, want %s", rel, got, want)
	}
}

func wantMiss(t *testing.T, rel string) {
	t.Helper()
	if got, ok := extract(t, rel); ok {
		t.Errorf("Extract(%q) = %s, want no match", rel, got)
	}
}

func TestIPv4DottedNotation(t *testing.T) {
	wantAddr(t, "10.0.0.7", "10.0.0.7")
	wantAddr(t, "app.10.0.0.7", "10.0.0.7")           // single-label prefix
	wantAddr(t, "a.b.192.168.1.250", "192.168.1.250") // deep prefix
	wantAddr(t, "127.0.0.1", "127.0.0.1")             // loopback for local dev
}

func TestIPv4DashedNotation(t *testing.T) {
	wantAddr(t, "10-0-0-7", "10.0.0.7")
	wantAddr(t, "app-10-0-0-7", "10.0.0.7") // dash prefix inside the label
	// A whole label to the left of the dashed label is a plain prefix.
	wantAddr(t, "deep.sub.app-192-168-1-9", "192.168.1.9")
}

func TestIPv4HexNotation(t *testing.T) {
	wantAddr(t, "0a000007", "10.0.0.7")
	wantAddr(t, "app-c0a80101", "192.168.1.1")
	// "deadbeef" is a real hex quad — documented nip.io-compatible behavior.
	wantAddr(t, "deadbeef", "222.173.190.239")
	// Exactly eight hex digits or nothing.
	wantMiss(t, "0a00007")   // 7 digits
	wantMiss(t, "0a0000077") // 9 digits
	wantMiss(t, "0a00000g")  // non-hex character
}

func TestIPv6DashedNotation(t *testing.T) {
	wantAddr(t, "--1", "::1")
	wantAddr(t, "2001-db8--7", "2001:db8::7")
	// A label without a dash never goes down the IPv6 path even when the
	// text would be a valid single-group abbreviation elsewhere.
	wantMiss(t, "fe80")
}

func TestNotationPrecedence(t *testing.T) {
	// When the last four labels are octets, that reading wins even if the
	// final label alone could be read as hex.
	wantAddr(t, "10.0.0.77", "10.0.0.77")
	// An eight-group IPv6 label must be read whole, not as a dashed IPv4
	// ending in "-0-0-0-42".
	wantAddr(t, "2001-db8-0-0-0-0-0-42", "2001:db8::42")
}

func TestNonAddressesNeverMatch(t *testing.T) {
	// Ordinary service names must fall through to registration/NXDOMAIN;
	// a magic false positive here would shadow real names.
	for _, rel := range []string{
		"app",
		"staging.api",
		"my-cool-service", // dashes but not an address
		"10.0.0.256",      // octet out of range
		"999-1-1-1",
		"10.01.0.7", // leading-zero octets are ambiguous and refused
		"app-10-00-0-7",
		"10-0-7", // only three dash parts
		"ＡＢＣ",    // full-width unicode
		"café-10-0-7",
	} {
		wantMiss(t, rel)
	}
	if _, ok := Extract(nil); ok {
		t.Error("Extract(nil) matched")
	}
}
