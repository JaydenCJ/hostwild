// CLI tests run the real Run() dispatcher in-process: exit codes, usage
// errors, offline `resolve` output, `sign` determinism, and one full
// loopback integration (serve → signed update → DNS query → acme) that
// exercises every moving part together on 127.0.0.1 ephemeral ports.
package cli

import (
	"bufio"
	"bytes"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

const testZone = "dev.example.test"

// run invokes the CLI and captures both streams.
func run(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := Run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestNoArgsIsUsageError(t *testing.T) {
	code, _, stderr := run()
	if code != ExitUsage || !strings.Contains(stderr, "Usage:") {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
}

func TestUnknownCommandIsUsageError(t *testing.T) {
	code, _, stderr := run("bogus")
	if code != ExitUsage || !strings.Contains(stderr, `unknown command "bogus"`) {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
}

func TestVersionAndHelp(t *testing.T) {
	code, stdout, _ := run("version")
	if code != ExitOK || stdout != "hostwild 0.1.0\n" {
		t.Fatalf("version: code=%d stdout=%q", code, stdout)
	}
	code, stdout, _ = run("--help")
	if code != ExitOK || !strings.Contains(stdout, "hostwild serve") {
		t.Fatalf("help: code=%d stdout=%q", code, stdout)
	}
}

func TestResolveMagicName(t *testing.T) {
	code, stdout, _ := run("resolve", "--zone", testZone, "app.10.0.0.7."+testZone)
	if code != ExitOK {
		t.Fatalf("exit %d, out=%q", code, stdout)
	}
	if !strings.Contains(stdout, "status: NOERROR") || !strings.Contains(stdout, "10.0.0.7") {
		t.Fatalf("output: %q", stdout)
	}
}

func TestResolveNegativeAnswersExitOne(t *testing.T) {
	code, stdout, _ := run("resolve", "--zone", testZone, "ghost."+testZone)
	if code != ExitNotFound || !strings.Contains(stdout, "NXDOMAIN") {
		t.Fatalf("nxdomain: code=%d out=%q", code, stdout)
	}
	code, stdout, _ = run("resolve", "--zone", testZone, "10.0.0.7.elsewhere.test")
	if code != ExitNotFound || !strings.Contains(stdout, "REFUSED") {
		t.Fatalf("out of zone: code=%d out=%q", code, stdout)
	}
}

func TestResolveSeededRecordAndFallback(t *testing.T) {
	code, stdout, _ := run("resolve", "--zone", testZone,
		"--record", "app=192.0.2.5", "app."+testZone)
	if code != ExitOK || !strings.Contains(stdout, "192.0.2.5") {
		t.Fatalf("seeded record: code=%d out=%q", code, stdout)
	}
	code, stdout, _ = run("resolve", "--zone", testZone,
		"--fallback", "10.9.9.9", "anything."+testZone)
	if code != ExitOK || !strings.Contains(stdout, "10.9.9.9") {
		t.Fatalf("fallback: code=%d out=%q", code, stdout)
	}
}

func TestResolveUsageErrors(t *testing.T) {
	code, _, stderr := run("resolve", "name.test")
	if code != ExitUsage || !strings.Contains(stderr, "--zone") {
		t.Fatalf("missing zone: code=%d stderr=%q", code, stderr)
	}
	code, _, stderr = run("resolve", "--zone", testZone, "--type", "MX", "x."+testZone)
	if code != ExitUsage || !strings.Contains(stderr, `unknown type "MX"`) {
		t.Fatalf("bad type: code=%d stderr=%q", code, stderr)
	}
}

func TestSignIsDeterministicWithPinnedTimestamp(t *testing.T) {
	args := []string{"sign", "--key", "k", "--method", "PUT",
		"--path", "/v1/records/app", "--body", `{"type":"A","value":"10.0.0.7"}`,
		"--timestamp", "1760000000"}
	_, first, _ := run(args...)
	code, second, _ := run(args...)
	if code != ExitOK || first != second {
		t.Fatalf("sign not deterministic:\n%q\n%q", first, second)
	}
	if !strings.Contains(first, "X-Hostwild-Timestamp: 1760000000") ||
		!strings.Contains(first, "X-Hostwild-Signature: ") {
		t.Fatalf("headers missing: %q", first)
	}
}

func TestSignRequiresKeyAndPath(t *testing.T) {
	if code, _, _ := run("sign", "--path", "/x"); code != ExitUsage {
		t.Fatalf("missing key accepted: %d", code)
	}
	if code, _, _ := run("sign", "--key", "k"); code != ExitUsage {
		t.Fatalf("missing path accepted: %d", code)
	}
}

func TestServeRequiresZoneAndKey(t *testing.T) {
	t.Setenv("HOSTWILD_KEY", "") // isolate from any ambient key
	if code, _, _ := run("serve"); code != ExitUsage {
		t.Fatalf("serve without --zone: %d", code)
	}
	if code, _, stderr := run("serve", "--zone", testZone); code != ExitUsage ||
		!strings.Contains(stderr, "--no-http") {
		t.Fatalf("serve without key: %d %q", code, stderr)
	}
}

// startServe launches `hostwild serve` on ephemeral loopback ports and
// parses the printed addresses. The returned stop function shuts it down.
func startServe(t *testing.T, extra ...string) (dnsAddr, httpBase string, stop func()) {
	t.Helper()
	pr, pw := io.Pipe()
	var stderr bytes.Buffer
	args := append([]string{"serve", "--zone", testZone,
		"--dns", "127.0.0.1:0", "--http", "127.0.0.1:0", "--key", "cli-test-key"}, extra...)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		Run(args, pw, &stderr)
		pw.Close()
	}()

	scanner := bufio.NewScanner(pr)
	deadline := time.After(10 * time.Second)
	lines := make(chan string)
	go func() {
		for scanner.Scan() {
			lines <- scanner.Text()
		}
		close(lines)
	}()
	for {
		select {
		case line, ok := <-lines:
			if !ok {
				t.Fatalf("serve exited early: %s", stderr.String())
			}
			if strings.HasPrefix(line, "dns   udp ") {
				dnsAddr = strings.TrimPrefix(line, "dns   udp ")
			}
			if strings.HasPrefix(line, "http  ") {
				httpBase = strings.TrimPrefix(line, "http  ")
			}
			if line == "ready" {
				stop = func() {
					// Closing the reader unblocks the pipe; the servers die
					// with the test process. Drain remaining lines.
					go func() {
						for range lines {
						}
					}()
					pr.Close()
				}
				return dnsAddr, httpBase, stop
			}
		case <-deadline:
			t.Fatalf("serve did not become ready; stderr: %s", stderr.String())
		}
	}
}

func TestServeUpdateQueryAcmeLoopback(t *testing.T) {
	dnsAddr, httpBase, stop := startServe(t, "--record", "seeded=203.0.113.9")
	defer stop()
	key := []string{"--key", "cli-test-key", "--api", httpBase}

	// 0. A record seeded with --record answers from the start.
	code0, stdout0, _ := run("query", "--server", dnsAddr, "seeded."+testZone)
	if code0 != ExitOK || !strings.Contains(stdout0, "203.0.113.9") {
		t.Fatalf("seeded record: code=%d out=%q", code0, stdout0)
	}

	// 1. Magic name answers immediately, no registration needed.
	code, stdout, stderr := run("query", "--server", dnsAddr, "app-10-0-0-7."+testZone)
	if code != ExitOK || !strings.Contains(stdout, "10.0.0.7") {
		t.Fatalf("magic query: code=%d out=%q err=%q", code, stdout, stderr)
	}

	// 2. Register a record over the signed API, then see it in DNS.
	code, stdout, stderr = run(append(append([]string{"update"}, key...), "api", "192.0.2.44")...)
	if code != ExitOK || !strings.Contains(stdout, "api."+testZone) {
		t.Fatalf("update: code=%d out=%q err=%q", code, stdout, stderr)
	}
	code, stdout, _ = run("query", "--server", dnsAddr, "api."+testZone)
	if code != ExitOK || !strings.Contains(stdout, "192.0.2.44") {
		t.Fatalf("query after update: code=%d out=%q", code, stdout)
	}

	// 3. The same query over TCP framing.
	code, stdout, _ = run("query", "--tcp", "--server", dnsAddr, "api."+testZone)
	if code != ExitOK || !strings.Contains(stdout, "192.0.2.44") {
		t.Fatalf("tcp query: code=%d out=%q", code, stdout)
	}

	// 4. DNS-01 helper: set, observe TXT, clear.
	code, stdout, stderr = run(append(append([]string{"acme"}, key...), "set", "api", "tok-xyz")...)
	if code != ExitOK {
		t.Fatalf("acme set: code=%d out=%q err=%q", code, stdout, stderr)
	}
	code, stdout, _ = run("query", "--server", dnsAddr, "--type", "TXT", "_acme-challenge.api."+testZone)
	if code != ExitOK || !strings.Contains(stdout, "tok-xyz") {
		t.Fatalf("challenge query: code=%d out=%q", code, stdout)
	}
	if code, _, _ = run(append(append([]string{"acme"}, key...), "clear", "api")...); code != ExitOK {
		t.Fatalf("acme clear failed: %d", code)
	}

	// 5. list shows the registered record.
	code, stdout, _ = run(append([]string{"list"}, key...)...)
	if code != ExitOK || !strings.Contains(stdout, "api."+testZone) {
		t.Fatalf("list: code=%d out=%q", code, stdout)
	}

	// 6. A wrong key must be rejected by the server.
	code, _, stderr = run("update", "--key", "wrong-key", "--api", httpBase, "evil", "10.6.6.6")
	if code != ExitRuntime || !strings.Contains(stderr, "authentication failed") {
		t.Fatalf("wrong key: code=%d err=%q", code, stderr)
	}

	// 7. delete removes the record; DNS then answers NXDOMAIN.
	code, _, stderr = run(append(append([]string{"update", "--delete"}, key...), "api")...)
	if code != ExitOK {
		t.Fatalf("delete: code=%d err=%q", code, stderr)
	}
	code, stdout, _ = run("query", "--server", dnsAddr, "api."+testZone)
	if code != ExitNotFound || !strings.Contains(stdout, "NXDOMAIN") {
		t.Fatalf("query after delete: code=%d out=%q", code, stdout)
	}
}

func TestQueryUnreachableServerIsRuntimeError(t *testing.T) {
	// A closed port on loopback fails fast — no external network involved.
	code, _, stderr := run("query", "--server", "127.0.0.1:1", "--timeout", "300ms", "x."+testZone)
	if code != ExitRuntime || stderr == "" {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
}

func TestUpdateInfersRecordTypes(t *testing.T) {
	_, httpBase, stop := startServe(t)
	defer stop()
	key := []string{"--key", "cli-test-key", "--api", httpBase}

	for value, wantType := range map[string]string{
		"10.0.0.7":    "A",
		"2001:db8::7": "AAAA",
		"hello-world": "TXT",
	} {
		code, stdout, stderr := run(append(append([]string{"update"}, key...), "typed", value)...)
		if code != ExitOK || !strings.HasPrefix(stdout, wantType+" ") {
			t.Fatalf("value %q: code=%d out=%q err=%q (want type %s)",
				value, code, stdout, stderr, wantType)
		}
	}
}
