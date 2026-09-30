// Package inspect extracts *facts* from a canonicalised tool call.
//
// It never decides anything. Cedar policies decide, using these facts as
// context ("code extracts facts, policy decides"). Keeping string parsing out
// of the policy language is what makes the policies short enough to show a jury.
package inspect

import (
	"context"
	"net"
	"net/netip"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/shlex"
	"golang.org/x/net/idna"

	"pnc3-gateway/internal/canon"
	"pnc3-gateway/internal/config"
)

type Destination struct {
	Arg         string   `json:"arg"`
	Kind        string   `json:"kind"`
	Value       string   `json:"value"`
	Host        string   `json:"host"`
	Allowlisted bool     `json:"allowlisted"`
	IPs         []string `json:"ips,omitempty"`
	Problem     string   `json:"problem,omitempty"`
}

// Facts are exported to Cedar as the request context.
type Facts struct {
	HasDestination           bool `json:"has_destination"`
	AllDestinationsAllowed   bool `json:"all_destinations_allowlisted"`
	PrivateDestination       bool `json:"private_destination"`
	MetadataDestination      bool `json:"metadata_destination"`
	LookalikeDestination     bool `json:"lookalike_destination"`
	DestinationUnresolvable  bool `json:"destination_unresolvable"`
	DestinationFromUntrusted bool `json:"destination_from_untrusted"`
	CarriesPrivateData       bool `json:"carries_private_data"`
	ContainsSecret           bool `json:"contains_secret"`
	PathEscape               bool `json:"path_escape"`
	CommandDestructive       bool `json:"command_destructive"`
	CommandInjection         bool `json:"command_injection"`
	SQLWrite                 bool `json:"sql_write"`
	Obfuscated               bool `json:"obfuscation_detected"`
	SessionTainted           bool `json:"session_tainted"`
	SessionHasPrivateData    bool `json:"session_has_private_data"`
}

// Map returns the facts as name -> bool (for Cedar and the audit log).
func (f Facts) Map() map[string]bool {
	return map[string]bool{
		"has_destination":              f.HasDestination,
		"all_destinations_allowlisted": f.AllDestinationsAllowed,
		"private_destination":          f.PrivateDestination,
		"metadata_destination":         f.MetadataDestination,
		"lookalike_destination":        f.LookalikeDestination,
		"destination_unresolvable":     f.DestinationUnresolvable,
		"destination_from_untrusted":   f.DestinationFromUntrusted,
		"carries_private_data":         f.CarriesPrivateData,
		"contains_secret":              f.ContainsSecret,
		"path_escape":                  f.PathEscape,
		"command_destructive":          f.CommandDestructive,
		"command_injection":            f.CommandInjection,
		"sql_write":                    f.SQLWrite,
		"obfuscation_detected":         f.Obfuscated,
		"session_tainted":              f.SessionTainted,
		"session_has_private_data":     f.SessionHasPrivateData,
	}
}

// SessionView is what the inspector needs to know about earlier calls in the session.
type SessionView struct {
	Tainted         bool
	HasPrivate      bool
	UntrustedValues map[string]struct{} // emails / hosts seen in untrusted content
	PrivateValues   map[string]struct{} // fingerprints of private data read earlier
}

type Report struct {
	Facts        Facts         `json:"facts"`
	Destinations []Destination `json:"destinations"`
	Findings     []string      `json:"findings"`
}

type Inspector struct {
	cfg      *config.Config
	resolver *net.Resolver
}

func New(cfg *config.Config) *Inspector {
	return &Inspector{cfg: cfg, resolver: net.DefaultResolver}
}

func (in *Inspector) Inspect(ctx context.Context, tool config.Tool, c *canon.Result, sess SessionView) Report {
	rep := Report{Facts: Facts{
		AllDestinationsAllowed: true,
		Obfuscated:             c.Obfuscated,
		SessionTainted:         sess.Tainted,
		SessionHasPrivateData:  sess.HasPrivate,
	}}
	f := &rep.Facts
	for _, n := range c.Notes {
		rep.Findings = append(rep.Findings, "decoded "+n)
	}

	for _, argPath := range c.Paths() {
		variants := c.Variants[argPath]
		kind := tool.Args[topLevel(argPath)]
		switch kind {
		case config.KindEmail:
			for _, d := range in.emailDestinations(argPath, variants) {
				in.recordDestination(ctx, &rep, d, sess)
			}
		case config.KindURL:
			for _, d := range in.urlDestinations(argPath, variants) {
				in.recordDestination(ctx, &rep, d, sess)
			}
		case config.KindPath:
			for _, v := range variants {
				if pathEscapes(v) {
					f.PathEscape = true
					rep.Findings = append(rep.Findings, "path escapes workspace: "+clip(v))
					break
				}
			}
		case config.KindCommand:
			for _, v := range variants {
				if m := destructiveCmd(v); m != "" {
					f.CommandDestructive = true
					rep.Findings = append(rep.Findings, "destructive command: "+m)
				}
				if m := injectedCmd(v); m != "" {
					f.CommandInjection = true
					rep.Findings = append(rep.Findings, "command injection pattern: "+m)
				}
			}
		case config.KindSQL:
			for _, v := range variants {
				if sqlWrite.MatchString(v) || stackedSQL.MatchString(v) {
					f.SQLWrite = true
					rep.Findings = append(rep.Findings, "write or stacked SQL statement")
					break
				}
			}
		}
	}

	all := c.All()
	if hits := FindSecrets(all); len(hits) > 0 {
		f.ContainsSecret = true
		sort.Strings(hits)
		rep.Findings = append(rep.Findings, "credential-shaped value: "+strings.Join(hits, ", "))
	}
	if len(sess.PrivateValues) > 0 {
		if fp := containsAny(all, sess.PrivateValues); fp != "" {
			f.CarriesPrivateData = true
			rep.Findings = append(rep.Findings, "carries private data read earlier in the session ("+mask(fp)+")")
		}
	}
	if !f.HasDestination {
		f.AllDestinationsAllowed = true
	}
	return rep
}

func (in *Inspector) recordDestination(ctx context.Context, rep *Report, d Destination, sess SessionView) {
	f := &rep.Facts
	f.HasDestination = true
	dests := in.cfg.Destinations

	if addr, err := netip.ParseAddr(strings.Trim(d.Host, "[]")); err == nil {
		// IP literals: never allowlisted by name; classify the address itself.
		d.IPs = []string{addr.String()}
		classifyIP(f, &d, addr)
	} else {
		if d.Kind == config.KindEmail {
			d.Allowlisted = config.HostAllowed(d.Host, dests.EmailDomains)
		} else {
			d.Allowlisted = config.HostAllowed(d.Host, dests.URLHosts)
		}
		if !d.Allowlisted {
			if near := lookalikeOf(d.Host, append(append([]string{}, dests.EmailDomains...), dests.URLHosts...)); near != "" {
				f.LookalikeDestination = true
				d.Problem = "lookalike of " + near
			}
		}
		// Only allowlisted URL hosts are resolved. Resolving an attacker's
		// hostname would itself leak data through DNS.
		if d.Allowlisted && d.Kind == config.KindURL {
			ips, err := in.resolve(ctx, d.Host)
			if err != nil || len(ips) == 0 {
				f.DestinationUnresolvable = true
				d.Problem = "does not resolve"
			}
			internal := config.HostAllowed(d.Host, dests.InternalHosts)
			for _, ip := range ips {
				d.IPs = append(d.IPs, ip.String())
				if !internal {
					classifyIP(f, &d, ip)
				}
			}
		}
	}
	if !d.Allowlisted {
		f.AllDestinationsAllowed = false
		if d.Problem == "" {
			d.Problem = "not on the allowlist"
		}
	}
	if _, ok := sess.UntrustedValues[strings.ToLower(d.Value)]; ok {
		f.DestinationFromUntrusted = true
	} else if _, ok := sess.UntrustedValues[d.Host]; ok && d.Kind == config.KindURL {
		f.DestinationFromUntrusted = true
	}
	rep.Destinations = append(rep.Destinations, d)
	if d.Problem != "" {
		rep.Findings = append(rep.Findings, d.Kind+" destination "+clip(d.Value)+": "+d.Problem)
	}
}

func classifyIP(f *Facts, d *Destination, ip netip.Addr) {
	ip = ip.Unmap()
	if isMetadata(ip) {
		f.MetadataDestination = true
		d.Problem = "cloud metadata address"
		return
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsMulticast() || cgnat.Contains(ip) {
		f.PrivateDestination = true
		d.Problem = "private or internal network address"
	}
}

var (
	cgnat       = netip.MustParsePrefix("100.64.0.0/10")
	metadataIPs = []netip.Addr{netip.MustParseAddr("169.254.169.254"), netip.MustParseAddr("fd00:ec2::254"), netip.MustParseAddr("100.100.100.200")}
)

func isMetadata(ip netip.Addr) bool {
	for _, m := range metadataIPs {
		if ip == m {
			return true
		}
	}
	return false
}

func (in *Inspector) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if s, ok := in.cfg.Destinations.StaticDNS[host]; ok {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, err
		}
		return []netip.Addr{a}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	return in.resolver.LookupNetIP(ctx, "ip", host)
}

var emailRe = regexp.MustCompile(`[^\s<>,;"']+@[^\s<>,;"']+`)

func (in *Inspector) emailDestinations(arg string, variants []string) []Destination {
	var out []Destination
	seen := map[string]bool{}
	for _, v := range variants {
		for _, addr := range emailRe.FindAllString(v, -1) {
			addr = strings.ToLower(strings.Trim(addr, ".()[]"))
			if seen[addr] {
				continue
			}
			seen[addr] = true
			domain := addr[strings.LastIndex(addr, "@")+1:]
			host, problem := toASCIIHost(domain)
			out = append(out, Destination{Arg: arg, Kind: config.KindEmail, Value: addr, Host: host, Problem: problem})
		}
	}
	return out
}

func (in *Inspector) urlDestinations(arg string, variants []string) []Destination {
	var out []Destination
	seen := map[string]bool{}
	for _, v := range variants {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		u, err := url.Parse(v)
		if err != nil || u.Host == "" {
			if strings.Contains(v, "://") {
				out = append(out, Destination{Arg: arg, Kind: config.KindURL, Value: v, Host: v, Problem: "unparseable URL"})
			}
			continue
		}
		d := Destination{Arg: arg, Kind: config.KindURL, Value: v}
		if u.Scheme != "http" && u.Scheme != "https" {
			d.Problem = "scheme " + u.Scheme + " is not allowed"
		}
		d.Host, _ = toASCIIHost(u.Hostname())
		if d.Problem != "" {
			d.Host = "(" + u.Scheme + ")" + d.Host // never matches an allowlist entry
		}
		out = append(out, d)
	}
	return out
}

// toASCIIHost lowercases, strips the trailing dot and converts IDN hosts to punycode,
// so "аcme.example" (Cyrillic a) becomes "xn--cme-8cd.example" and fails the allowlist.
func toASCIIHost(h string) (string, string) {
	h = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
	a, err := idna.Lookup.ToASCII(h)
	if err != nil {
		return h, "invalid international domain name"
	}
	return a, ""
}

// lookalikeOf maps common confusable characters to ASCII and compares with the allowlist.
func lookalikeOf(host string, allowed []string) string {
	u, err := idna.ToUnicode(host)
	if err != nil {
		u = host
	}
	skel := skeleton(u)
	for _, a := range allowed {
		a = strings.TrimPrefix(strings.ToLower(a), "*.")
		if skel == a || strings.HasSuffix(skel, "."+a) {
			return a
		}
	}
	return ""
}

var confusables = map[rune]rune{
	'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ј': 'j', 'ѕ': 's',
	'ԁ': 'd', 'һ': 'h', 'ӏ': 'l', 'ν': 'v', 'ο': 'o', 'α': 'a', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'τ': 't',
	'0': 'o', '1': 'l', 'ɑ': 'a', 'ɡ': 'g', 'ⅼ': 'l', 'ｍ': 'm',
}

func skeleton(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if c, ok := confusables[r]; ok {
			b.WriteRune(c)
		} else {
			b.WriteRune(r)
		}
	}
	return strings.ReplaceAll(b.String(), "rn", "m")
}

func pathEscapes(p string) bool {
	if strings.ContainsRune(p, 0) {
		return true
	}
	p = strings.ReplaceAll(p, "\\", "/")
	if strings.HasPrefix(p, "/") || strings.HasPrefix(p, "~") || (len(p) > 1 && p[1] == ':') {
		return true
	}
	joined := path.Clean(path.Join("/workspace", p))
	return joined != "/workspace" && !strings.HasPrefix(joined, "/workspace/")
}

var (
	destructivePatterns = []*regexp.Regexp{
		regexp.MustCompile(`\brm\s+(-[a-z]*[rf][a-z]*\s+)*-[a-z]*[rf]`),
		regexp.MustCompile(`\brm\s+.*--(recursive|force|no-preserve-root)`),
		regexp.MustCompile(`\b(mkfs(\.\w+)?|shutdown|reboot|halt|poweroff)\b`),
		regexp.MustCompile(`\bdd\s+.*\bof=/dev/`),
		regexp.MustCompile(`:\(\)\s*\{`),
		regexp.MustCompile(`\bchmod\s+(-r\s+)?[0-7]*777\s+/`),
		regexp.MustCompile(`>\s*/dev/(sd|nvme|hd)`),
		regexp.MustCompile(`\b(drop|truncate)\s+(table|database)\b`),
		regexp.MustCompile(`\bgit\s+push\s+.*(--force|-f)\b`),
		regexp.MustCompile(`\bkill\s+-9\s+(-1|1)\b`),
	}
	injectionPatterns = []*regexp.Regexp{
		regexp.MustCompile("[;&|`\n]"),
		regexp.MustCompile(`\$\(|\$\{`),
		regexp.MustCompile(`[<>]`),
		regexp.MustCompile(`--(upload-pack|exec|receive-pack)\b`),
		regexp.MustCompile(`(^|\s)-c\s+\S*=`),
		regexp.MustCompile(`\b(curl|wget|nc|ncat)\b.*\|\s*(sh|bash)`),
	}
	sqlWrite   = regexp.MustCompile(`(?i)\b(drop|delete|update|insert|alter|truncate|grant|revoke|create)\b`)
	stackedSQL = regexp.MustCompile(`;\s*\S`)
)

func destructiveCmd(cmd string) string {
	lc := strings.ToLower(cmd)
	for _, p := range destructivePatterns {
		if m := p.FindString(lc); m != "" {
			return m
		}
	}
	// Also inspect the tokenised form, which removes quoting tricks like r''m.
	if toks, err := shlex.Split(lc); err == nil {
		joined := strings.Join(toks, " ")
		for _, p := range destructivePatterns {
			if m := p.FindString(joined); m != "" {
				return m
			}
		}
	}
	return ""
}

func injectedCmd(cmd string) string {
	for _, p := range injectionPatterns {
		if m := p.FindString(cmd); m != "" {
			return strings.TrimSpace(m)
		}
	}
	return ""
}

func containsAny(values []string, set map[string]struct{}) string {
	for _, v := range values {
		lv := strings.ToLower(v)
		digits := onlyDigits(lv)
		for fp := range set {
			if strings.HasPrefix(fp, "#") {
				if len(digits) >= 8 && strings.Contains(digits, fp[1:]) {
					return fp[1:]
				}
				continue
			}
			if strings.Contains(lv, fp) {
				return fp
			}
		}
	}
	return ""
}

func onlyDigits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func topLevel(p string) string {
	if i := strings.IndexAny(p, ".["); i >= 0 {
		return p[:i]
	}
	return p
}

func clip(s string) string {
	if len(s) > 80 {
		return s[:77] + "..."
	}
	return s
}

func mask(s string) string {
	if len(s) <= 6 {
		return "***"
	}
	return s[:3] + "***" + s[len(s)-2:]
}
