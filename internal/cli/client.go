package cli

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/JaydenCJ/hostwild/internal/hmacauth"
)

// This file is the client side of the update API: `sign` for scripting
// with curl, and `update` / `acme` / `list` as ready-made clients. All of
// them talk only to the URL you give them (loopback by default).

// runSign prints curl-ready authentication headers for a request, so any
// tool that can set headers can drive the API without linking hostwild.
func runSign(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	var (
		method = fs.String("method", "PUT", "HTTP method to sign")
		path   = fs.String("path", "", "request path, e.g. /v1/records/app (required)")
		body   = fs.String("body", "", "request body to sign (JSON)")
		ts     = fs.Int64("timestamp", 0, "Unix timestamp (default: now)")
		keys   keyFlags
	)
	keys.register(fs)
	if !parseFlags(fs, args, stderr) {
		return ExitUsage
	}
	if *path == "" || fs.NArg() != 0 {
		fmt.Fprintln(stderr, "hostwild sign: --path is required and takes no positional arguments")
		return ExitUsage
	}
	key, err := keys.resolveKey()
	if err != nil {
		fmt.Fprintf(stderr, "hostwild sign: %v\n", err)
		return ExitUsage
	}
	when := *ts
	if when == 0 {
		when = time.Now().Unix()
	}
	sig := hmacauth.Sign(key, strings.ToUpper(*method), *path, when, []byte(*body))
	fmt.Fprintf(stdout, "%s: %d\n", hmacauth.HeaderTimestamp, when)
	fmt.Fprintf(stdout, "%s: %s\n", hmacauth.HeaderSignature, sig)
	return ExitOK
}

// apiFlags are shared by every API client subcommand.
type apiFlags struct {
	base string
	keys keyFlags
}

func (a *apiFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&a.base, "api", "http://127.0.0.1:8053", "update-API base URL")
	a.keys.register(fs)
}

// call signs and sends one request, decodes the JSON response, and
// returns an error carrying the server's message on non-2xx statuses.
func (a *apiFlags) call(method, path string, body []byte) (map[string]any, error) {
	key, err := a.keys.resolveKey()
	if err != nil {
		return nil, err
	}
	u, err := url.JoinPath(a.base, path)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(method, u, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	ts := time.Now().Unix()
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(hmacauth.HeaderTimestamp, fmt.Sprintf("%d", ts))
	req.Header.Set(hmacauth.HeaderSignature, hmacauth.Sign(key, method, req.URL.Path, ts, body))
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		return nil, fmt.Errorf("server returned %s with a non-JSON body", resp.Status)
	}
	if resp.StatusCode/100 != 2 {
		if msg, ok := decoded["error"].(string); ok {
			return nil, fmt.Errorf("server: %s (%s)", msg, resp.Status)
		}
		return nil, fmt.Errorf("server returned %s", resp.Status)
	}
	return decoded, nil
}

// runUpdate registers or deletes a record through the API.
func runUpdate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	var (
		del   = fs.Bool("delete", false, "delete all records at <name> instead of registering")
		rtype = fs.String("type", "", "record type; inferred from the value when omitted")
		ttl   = fs.Uint("ttl", 0, "record TTL in seconds (0 = zone default)")
		apif  apiFlags
	)
	apif.register(fs)
	if !parseFlags(fs, args, stderr) {
		return ExitUsage
	}
	if *del {
		if fs.NArg() != 1 {
			fmt.Fprintln(stderr, "hostwild update: usage: update --delete <name>")
			return ExitUsage
		}
		out, err := apif.call(http.MethodDelete, "/v1/records/"+fs.Arg(0), nil)
		if err != nil {
			fmt.Fprintf(stderr, "hostwild update: %v\n", err)
			return ExitRuntime
		}
		fmt.Fprintf(stdout, "deleted %v (serial %v)\n", out["name"], out["serial"])
		return ExitOK
	}
	if fs.NArg() != 2 {
		fmt.Fprintln(stderr, "hostwild update: usage: update [flags] <name> <value>")
		return ExitUsage
	}
	name, value := fs.Arg(0), fs.Arg(1)
	t := *rtype
	if t == "" {
		// Infer: a parseable address is A/AAAA, everything else is TXT.
		if addr, err := netip.ParseAddr(value); err == nil {
			if addr.Unmap().Is4() {
				t = "A"
			} else {
				t = "AAAA"
			}
		} else {
			t = "TXT"
		}
	}
	body, err := json.Marshal(map[string]any{"type": t, "value": value, "ttl": *ttl})
	if err != nil {
		fmt.Fprintf(stderr, "hostwild update: %v\n", err)
		return ExitRuntime
	}
	out, err := apif.call(http.MethodPut, "/v1/records/"+name, body)
	if err != nil {
		fmt.Fprintf(stderr, "hostwild update: %v\n", err)
		return ExitRuntime
	}
	fmt.Fprintf(stdout, "%v %v -> %s (serial %v)\n", out["type"], out["fqdn"], value, out["serial"])
	return ExitOK
}

// runAcme sets or clears the _acme-challenge TXT record for a name.
func runAcme(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("acme", flag.ContinueOnError)
	var apif apiFlags
	apif.register(fs)
	if !parseFlags(fs, args, stderr) {
		return ExitUsage
	}
	switch {
	case fs.NArg() == 3 && fs.Arg(0) == "set":
		body, err := json.Marshal(map[string]string{"value": fs.Arg(2)})
		if err != nil {
			fmt.Fprintf(stderr, "hostwild acme: %v\n", err)
			return ExitRuntime
		}
		out, err := apif.call(http.MethodPut, "/v1/acme/"+fs.Arg(1), body)
		if err != nil {
			fmt.Fprintf(stderr, "hostwild acme: %v\n", err)
			return ExitRuntime
		}
		fmt.Fprintf(stdout, "TXT %v set (serial %v)\n", out["fqdn"], out["serial"])
		return ExitOK
	case fs.NArg() == 2 && fs.Arg(0) == "clear":
		out, err := apif.call(http.MethodDelete, "/v1/acme/"+fs.Arg(1), nil)
		if err != nil {
			fmt.Fprintf(stderr, "hostwild acme: %v\n", err)
			return ExitRuntime
		}
		fmt.Fprintf(stdout, "TXT %v cleared\n", out["fqdn"])
		return ExitOK
	default:
		fmt.Fprintln(stderr, "hostwild acme: usage: acme [flags] set <name> <value> | clear <name>")
		return ExitUsage
	}
}

// runList prints every registered record.
func runList(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	var apif apiFlags
	apif.register(fs)
	if !parseFlags(fs, args, stderr) {
		return ExitUsage
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "hostwild list: takes no positional arguments")
		return ExitUsage
	}
	out, err := apif.call(http.MethodGet, "/v1/records", nil)
	if err != nil {
		fmt.Fprintf(stderr, "hostwild list: %v\n", err)
		return ExitRuntime
	}
	entries, _ := out["entries"].([]any)
	noun := "names"
	if len(entries) == 1 {
		noun = "name"
	}
	fmt.Fprintf(stdout, "zone %v — %d registered %s\n", out["zone"], len(entries), noun)
	for _, e := range entries {
		entry, _ := e.(map[string]any)
		recs, _ := entry["records"].([]any)
		for _, r := range recs {
			rec, _ := r.(map[string]any)
			val := rec["value"]
			if val == nil {
				val = rec["txt"]
			}
			fmt.Fprintf(stdout, "  %-30v %-5v %v\n", entry["fqdn"], rec["type"], val)
		}
	}
	return ExitOK
}
