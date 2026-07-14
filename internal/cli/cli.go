// Package cli implements the hostwild command-line interface. Run takes
// argv and two writers and returns an exit code, so the whole surface is
// testable in-process without building a binary.
package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/JaydenCJ/hostwild/internal/version"
)

// Exit codes, documented in the README. ExitNotFound is the
// machine-readable verdict of `resolve` and `query` for empty answers.
const (
	ExitOK       = 0
	ExitNotFound = 1
	ExitUsage    = 2
	ExitRuntime  = 3
)

// Run dispatches argv and returns the process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return ExitUsage
	}
	switch args[0] {
	case "serve":
		return runServe(args[1:], stdout, stderr)
	case "resolve":
		return runResolve(args[1:], stdout, stderr)
	case "query":
		return runQuery(args[1:], stdout, stderr)
	case "sign":
		return runSign(args[1:], stdout, stderr)
	case "update":
		return runUpdate(args[1:], stdout, stderr)
	case "acme":
		return runAcme(args[1:], stdout, stderr)
	case "list":
		return runList(args[1:], stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "hostwild %s\n", version.Version)
		return ExitOK
	case "help", "--help", "-h":
		usage(stdout)
		return ExitOK
	default:
		fmt.Fprintf(stderr, "hostwild: unknown command %q\n\n", args[0])
		usage(stderr)
		return ExitUsage
	}
}

func usage(w io.Writer) {
	fmt.Fprintf(w, `hostwild %s — self-hosted wildcard dev DNS

Usage:
  hostwild serve   --zone <apex> [--dns addr] [--http addr] [--key ...]
  hostwild resolve --zone <apex> [--type T] <fqdn>       offline dry-run
  hostwild query   --server addr [--type T] [--tcp] <fqdn>
  hostwild update  --key ... [--api url] <name> <value>  register a record
  hostwild update  --key ... --delete <name>             remove records
  hostwild acme    --key ... set|clear <name> [value]    DNS-01 helper
  hostwild list    --key ... [--api url]                 registered records
  hostwild sign    --key ... --method M --path P         curl-ready headers
  hostwild version

Exit codes: 0 ok, 1 no answer, 2 usage error, 3 runtime error.
Run any subcommand with -h for its full flag list.
`, version.Version)
}

// keyFlags is the shared secret-key input, accepted as a literal, a file,
// or the HOSTWILD_KEY environment variable (in that precedence order).
type keyFlags struct {
	key     string
	keyFile string
}

func (k *keyFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&k.key, "key", "", "shared HMAC key (prefer --key-file or HOSTWILD_KEY)")
	fs.StringVar(&k.keyFile, "key-file", "", "file containing the shared HMAC key")
}

// resolveKey returns the key bytes or an error naming every source tried.
func (k *keyFlags) resolveKey() ([]byte, error) {
	if k.key != "" {
		return []byte(k.key), nil
	}
	if k.keyFile != "" {
		data, err := os.ReadFile(k.keyFile)
		if err != nil {
			return nil, fmt.Errorf("read key file: %w", err)
		}
		key := strings.TrimSpace(string(data))
		if key == "" {
			return nil, fmt.Errorf("key file %s is empty", k.keyFile)
		}
		return []byte(key), nil
	}
	if env := os.Getenv("HOSTWILD_KEY"); env != "" {
		return []byte(env), nil
	}
	return nil, fmt.Errorf("no key: pass --key, --key-file, or set HOSTWILD_KEY")
}

// parseFlags runs a FlagSet against args with errors routed to stderr,
// returning false (usage error) on failure.
func parseFlags(fs *flag.FlagSet, args []string, stderr io.Writer) bool {
	fs.SetOutput(stderr)
	return fs.Parse(args) == nil
}
