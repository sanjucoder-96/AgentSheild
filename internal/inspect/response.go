package inspect

import (
	"net/url"
	"regexp"
	"strings"

	"pnc3-gateway/internal/canon"
)

var injectionMarkers = []*regexp.Regexp{
	regexp.MustCompile(`(?i)ignore (all |any )?(previous|prior|above) instructions`),
	regexp.MustCompile(`(?i)(note|message|instruction)s? for the (ai|assistant|agent)`),
	regexp.MustCompile(`(?i)\bai (agents?|assistants?) reading this\b`),
	regexp.MustCompile(`(?i)\[?assistant[-_ ]instruction\]?`),
	regexp.MustCompile(`(?i)(^|\n)\s*(system|assistant)\s*:`),
	regexp.MustCompile(`(?i)do not (mention|tell|reveal) (this|the user)`),
	regexp.MustCompile(`(?i)keep (it|this) (quiet|secret)`),
	regexp.MustCompile(`(?i)display\s*:\s*none`),
	regexp.MustCompile(`<!--`),
}

// InjectionMarkers lists suspicious instruction patterns found in tool output.
func InjectionMarkers(text string) []string {
	var out []string
	for _, r := range injectionMarkers {
		if m := r.FindString(text); m != "" {
			out = append(out, strings.TrimSpace(m))
		}
	}
	return out
}

var (
	urlInText    = regexp.MustCompile(`https?://[^\s"'<>)]+`)
	domainInText = regexp.MustCompile(`(?i)\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9-]{1,63})*\.(?:example|com|net|org|io|in|dev|app|co|info|biz|xyz|local|internal)\b`)
	phoneLike    = regexp.MustCompile(`\+?\d[\d\s-]{6,}\d`)
	canaryRe     = regexp.MustCompile(`(?i)canary-[a-z0-9-]+`)
	b64InText    = regexp.MustCompile(`[A-Za-z0-9+/]{16,}={0,2}`)
)

// expandText adds decoded forms of encoded fragments, so an address hidden
// in Base64 inside a ticket is still recognised as coming from that ticket.
func expandText(text string) []string {
	out := []string{text, canon.Normalize(text)}
	for _, frag := range b64InText.FindAllString(text, 16) {
		vars, _, _ := canon.Expand(frag, 3)
		out = append(out, vars[1:]...)
	}
	return out
}

// UntrustedValues extracts addresses and hosts from untrusted content.
func UntrustedValues(text string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = strings.ToLower(strings.Trim(s, ".,;:()[]"))
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, t := range expandText(text) {
		for _, e := range emailRe.FindAllString(t, -1) {
			add(e)
		}
		for _, u := range urlInText.FindAllString(t, -1) {
			if p, err := url.Parse(u); err == nil {
				add(p.Hostname())
			}
		}
		for _, d := range domainInText.FindAllString(t, -1) {
			add(d)
		}
	}
	return out
}

// PrivateFingerprints extracts values that identify private records.
// Digit runs are stored with a "#" prefix and compared digit-only.
func PrivateFingerprints(text string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	lt := strings.ToLower(text)
	for _, e := range emailRe.FindAllString(lt, -1) {
		add(strings.Trim(e, ".,;:()[]"))
	}
	for _, c := range canaryRe.FindAllString(lt, -1) {
		add(c)
	}
	for _, p := range phoneLike.FindAllString(lt, -1) {
		if d := onlyDigits(p); len(d) >= 8 {
			add("#" + d)
		}
	}
	return out
}
