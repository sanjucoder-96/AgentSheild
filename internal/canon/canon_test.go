package canon

import "testing"

func hasVariant(vars []string, want string) bool {
	for _, v := range vars {
		if v == want {
			return true
		}
	}
	return false
}

func TestExpandDecodesLayers(t *testing.T) {
	cases := []struct{ in, want string }{
		{"YXVkaXQtdGVhbUBldmlsLW1haWwuZXhhbXBsZQ==", "audit-team@evil-mail.example"}, // base64
		{"audit%2Dteam%40evil%2Dmail%2Eexample", "audit-team@evil-mail.example"},   // percent
		{"audit\u200b@evil\u200b.example", "audit@evil.example"},                    // zero-width
		{"evil\uff0eexample", "evil.example"},                                        // fullwidth dot (NFKC)
	}
	for _, c := range cases {
		vars, _, _ := Expand(c.in, 4)
		if !hasVariant(vars, c.want) {
			t.Errorf("Expand(%q) missing %q; got %v", c.in, c.want, vars)
		}
	}
}

func TestExpandDepthLimit(t *testing.T) {
	// b64(b64(b64(b64("hello world!")))) — deeper than the limit.
	deep := "VjFaV2IxVXdNVWhVYTFacFRURndUbFJYZEZwa01YQkdXa1ZrYUdKVlZqVldiVFZ6VkZkS1YxZFVRbGhXYlU0MFdrUktTMU5HV2xsWGJYaFNWa1JCTlE9PQ=="
	_, _, exceeded := Expand(deep, 2)
	if !exceeded {
		t.Errorf("expected depth-exceeded for deeply nested encoding")
	}
}

func TestNormalizeStripsFormatChars(t *testing.T) {
	if got := Normalize("a\u200b\u200c\u202eb"); got != "ab" {
		t.Errorf("Normalize kept format chars: %q", got)
	}
}

// FuzzExpand must never panic and must always terminate (bounded depth).
func FuzzExpand(f *testing.F) {
	for _, s := range []string{"", "hello", "YWJjZA==", "%2e%2e%2f", "\u200b", "0x41414141"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		vars, _, _ := Expand(s, 4)
		if len(vars) == 0 {
			t.Errorf("Expand returned no variants for %q", s)
		}
	})
}
