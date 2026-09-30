// Package canon turns every string argument into the set of forms a tool might
// eventually act on. Checks run on *all* of them, never only the raw string:
//
//	raw -> NFKC + strip invisible characters -> decode (percent, HTML entities,
//	escapes, Base64, hex) repeatedly, up to a bounded depth.
//
// If a value is still decodable after the depth limit, the call is refused
// outright (excessive_encoding): legitimate agents do not need five layers.
package canon

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

type Result struct {
	// Variants maps an argument path (e.g. "to", "items[0].url") to every form of its value.
	Variants      map[string][]string
	Obfuscated    bool
	DepthExceeded bool
	Notes         []string
}

// All returns every variant of every argument (used for secret scanning).
func (r *Result) All() []string {
	var out []string
	for _, v := range r.Variants {
		out = append(out, v...)
	}
	return out
}

func (r *Result) Paths() []string {
	out := make([]string, 0, len(r.Variants))
	for p := range r.Variants {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// Canonicalize walks the argument tree.
func Canonicalize(args map[string]any, maxDepth int) *Result {
	r := &Result{Variants: map[string][]string{}}
	for k, v := range args {
		walk(r, k, v, maxDepth)
	}
	return r
}

func walk(r *Result, path string, v any, maxDepth int) {
	switch t := v.(type) {
	case string:
		vars, notes, exceeded := Expand(t, maxDepth)
		r.Variants[path] = vars
		if len(notes) > 0 {
			r.Obfuscated = true
			for _, n := range notes {
				r.Notes = append(r.Notes, path+": "+n)
			}
		}
		if exceeded {
			r.DepthExceeded = true
		}
	case map[string]any:
		for k, sub := range t {
			walk(r, path+"."+k, sub, maxDepth)
		}
	case []any:
		for i, sub := range t {
			walk(r, fmt.Sprintf("%s[%d]", path, i), sub, maxDepth)
		}
	default:
		r.Variants[path] = []string{fmt.Sprint(t)}
	}
}

// Expand returns the raw string plus every normalised and decoded form.
func Expand(s string, maxDepth int) (variants []string, notes []string, depthExceeded bool) {
	seen := map[string]bool{}
	add := func(v string) bool {
		if seen[v] {
			return false
		}
		seen[v] = true
		variants = append(variants, v)
		return true
	}
	add(s)
	cur := Normalize(s)
	if add(cur) {
		notes = append(notes, "unicode normalised / invisible characters removed")
	}
	for depth := 0; ; depth++ {
		decoded, kind, ok := decodeOnce(cur)
		if !ok {
			break
		}
		if depth >= maxDepth {
			return variants, append(notes, "still encoded after "+strconv.Itoa(maxDepth)+" layers"), true
		}
		cur = Normalize(decoded)
		if !add(cur) {
			break
		}
		notes = append(notes, kind+" decoded")
	}
	// Encoded fragments embedded in longer text ("send it to <base64> please").
	for _, frag := range embeddedB64.FindAllString(cur, 8) {
		if d, ok := tryBase64(frag); ok && add(Normalize(d)) {
			notes = append(notes, "embedded base64 decoded")
		}
	}
	return variants, notes, false
}

// Normalize applies NFKC and removes zero-width, bidi-control and other format characters.
func Normalize(s string) string {
	s = norm.NFKC.String(s)
	return strings.Map(func(r rune) rune {
		if unicode.Is(unicode.Cf, r) { // format chars: ZWSP, ZWJ, bidi overrides, BOM...
			return -1
		}
		return r
	}, s)
}

var (
	percentRe   = regexp.MustCompile(`%[0-9A-Fa-f]{2}`)
	entityRe    = regexp.MustCompile(`&(#[0-9]+|#[xX][0-9a-fA-F]+|[a-zA-Z]+);`)
	escapeRe    = regexp.MustCompile(`\\(u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2})`)
	base64Re    = regexp.MustCompile(`^[A-Za-z0-9+/_-]{8,}={0,2}$`)
	hexRe       = regexp.MustCompile(`^(0x)?([0-9a-fA-F]{2}){4,}$`)
	embeddedB64 = regexp.MustCompile(`[A-Za-z0-9+/]{16,}={0,2}`)
)

func decodeOnce(s string) (string, string, bool) {
	t := strings.TrimSpace(s)
	if percentRe.MatchString(t) {
		if d, err := url.PathUnescape(t); err == nil && d != t {
			return d, "percent-encoding", true
		}
	}
	if entityRe.MatchString(t) {
		if d := html.UnescapeString(t); d != t {
			return d, "HTML entities", true
		}
	}
	if escapeRe.MatchString(t) {
		if d := unescape(t); d != t {
			return d, "escape sequences", true
		}
	}
	if hexRe.MatchString(t) {
		if b, err := hex.DecodeString(strings.TrimPrefix(t, "0x")); err == nil && printable(b) {
			return string(b), "hex", true
		}
	}
	if base64Re.MatchString(t) {
		if d, ok := tryBase64(t); ok {
			return d, "base64", true
		}
	}
	return "", "", false
}

func tryBase64(s string) (string, bool) {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil && len(b) >= 4 && printable(b) {
			return string(b), true
		}
	}
	return "", false
}

// DecodesToText reports whether a token is encoded text (as opposed to random key material).
func DecodesToText(s string) bool {
	_, ok := tryBase64(s)
	return ok
}

func printable(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	total, good := 0, 0
	for _, r := range string(b) {
		total++
		if unicode.IsPrint(r) || r == '\n' || r == '\t' || r == '\r' {
			good++
		}
	}
	return total > 0 && good*100/total >= 95
}

func unescape(s string) string {
	return escapeRe.ReplaceAllStringFunc(s, func(m string) string {
		n, err := strconv.ParseUint(m[2:], 16, 32)
		if err != nil {
			return m
		}
		return string(rune(n))
	})
}
