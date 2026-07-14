package cli

import (
	"flag"
	"fmt"
	"io"

	"github.com/JaydenCJ/hostwild/internal/dnswire"
	"github.com/JaydenCJ/hostwild/internal/resolver"
	"github.com/JaydenCJ/hostwild/internal/zone"
)

// runResolve answers a question with the in-process engine — no server,
// no socket. It is the dry-run twin of `serve`: same resolver, same
// precedence, so you can verify what a name would return before exposing
// anything to the network.
func runResolve(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("resolve", flag.ContinueOnError)
	var (
		zoneName = fs.String("zone", "", "zone apex, e.g. dev.example.test (required)")
		qtype    = fs.String("type", "A", "question type: A, AAAA, TXT, NS, SOA, or ANY")
		apex     = fs.String("apex", "", "address to answer for the zone apex")
		fallback = fs.String("fallback", "", "catch-all address for unmatched names")
		state    = fs.String("state", "", "JSON state file with registered records")
		records  multiFlag
	)
	fs.Var(&records, "record", "seed a static record, name=address (repeatable)")
	if !parseFlags(fs, args, stderr) {
		return ExitUsage
	}
	if *zoneName == "" || fs.NArg() != 1 {
		fmt.Fprintln(stderr, "hostwild resolve: usage: resolve --zone <apex> [flags] <fqdn>")
		return ExitUsage
	}
	t, ok := dnswire.ParseType(*qtype)
	if !ok {
		fmt.Fprintf(stderr, "hostwild resolve: unknown type %q\n", *qtype)
		return ExitUsage
	}

	cfg := resolver.Config{Zone: dnswire.CanonicalName(*zoneName)}
	var err error
	if cfg.ApexA, err = optionalAddr(*apex); err != nil {
		fmt.Fprintf(stderr, "hostwild resolve: --apex: %v\n", err)
		return ExitUsage
	}
	if cfg.Fallback, err = optionalAddr(*fallback); err != nil {
		fmt.Fprintf(stderr, "hostwild resolve: --fallback: %v\n", err)
		return ExitUsage
	}
	store := zone.NewStore(*state)
	if err := store.Load(); err != nil {
		fmt.Fprintf(stderr, "hostwild resolve: %v\n", err)
		return ExitRuntime
	}
	if err := seedRecords(store, records); err != nil {
		fmt.Fprintf(stderr, "hostwild resolve: %v\n", err)
		return ExitUsage
	}

	q := dnswire.Question{Name: dnswire.CanonicalName(fs.Arg(0)), Type: t, Class: dnswire.ClassINET}
	res := resolver.New(cfg, store).Resolve(q)
	return printResult(stdout, res.RCode, res.Answers, res.Authority)
}

// printResult renders answers zone-file style; shared with `query`.
func printResult(w io.Writer, rcode uint8, answers, authority []dnswire.RR) int {
	fmt.Fprintf(w, ";; status: %s, answers: %d\n", dnswire.RCodeName(rcode), len(answers))
	for _, rr := range answers {
		fmt.Fprintln(w, rr.String())
	}
	for _, rr := range authority {
		fmt.Fprintf(w, ";; authority: %s\n", rr.String())
	}
	if rcode != dnswire.RCodeNoError || len(answers) == 0 {
		return ExitNotFound
	}
	return ExitOK
}
