package inspect

import (
	"math"
	"regexp"

	"pnc3-gateway/internal/canon"
)

// Rules modelled on Gitleaks' most common detectors.
var secretRules = []struct {
	Name string
	Re   *regexp.Regexp
}{
	{"aws_access_key", regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{"github_token", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b`)},
	{"slack_token", regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}`)},
	{"openai_key", regexp.MustCompile(`\bsk-(proj-)?[A-Za-z0-9_-]{20,}`)},
	{"anthropic_key", regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{20,}`)},
	{"google_api_key", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)},
	{"stripe_key", regexp.MustCompile(`\b[rs]k_live_[0-9a-zA-Z]{16,}`)},
	{"private_key", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
	{"jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)},
	{"generic_secret_assignment", regexp.MustCompile(`(?i)\b(api[_-]?key|secret|passwd|password|token)\s*[:=]\s*['"]?[A-Za-z0-9/+_\-]{16,}`)},
}

var tokenRe = regexp.MustCompile(`[A-Za-z0-9+/=_\-]{32,}`)

// FindSecrets returns the names of secret rules matched by any of the strings.
func FindSecrets(values []string) []string {
	hits := map[string]bool{}
	for _, v := range values {
		for _, r := range secretRules {
			if r.Re.MatchString(v) {
				hits[r.Name] = true
			}
		}
		for _, tok := range tokenRe.FindAllString(v, 16) {
			if looksRandom(tok) && !canon.DecodesToText(tok) {
				hits["high_entropy_token"] = true
			}
		}
	}
	out := make([]string, 0, len(hits))
	for h := range hits {
		out = append(out, h)
	}
	return out
}

// Redact masks secrets in tool output before it reaches the agent.
func Redact(s string) (string, bool) {
	changed := false
	for _, r := range secretRules {
		if r.Re.MatchString(s) {
			s = r.Re.ReplaceAllString(s, "[REDACTED:"+r.Name+"]")
			changed = true
		}
	}
	return s, changed
}

func looksRandom(s string) bool {
	var upper, lower, digit bool
	freq := map[rune]float64{}
	for _, r := range s {
		freq[r]++
		switch {
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= '0' && r <= '9':
			digit = true
		}
	}
	if !(upper && lower && digit) {
		return false
	}
	var h float64
	n := float64(len(s))
	for _, c := range freq {
		p := c / n
		h -= p * math.Log2(p)
	}
	return h >= 4.3
}
