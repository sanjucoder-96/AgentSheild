package auth

import (
	"strings"
	"testing"
	"time"
)

func TestLoginChecksUserAndPassword(t *testing.T) {
	a, err := NewAdmin("admin", "correct-horse-battery", "", "s3cret-session-key-0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	if !a.CheckLogin("admin", "correct-horse-battery") {
		t.Error("valid login rejected")
	}
	if a.CheckLogin("admin", "wrong") || a.CheckLogin("root", "correct-horse-battery") {
		t.Error("invalid login accepted")
	}
}

func TestHashedPasswordRoundTrip(t *testing.T) {
	h, err := HashPassword("a-long-enough-password")
	if err != nil || !strings.HasPrefix(h, "b64:") || strings.Contains(h, "$") {
		t.Fatalf("hash should be b64-wrapped with no '$': %q %v", h, err)
	}
	a, err := NewAdmin("admin", "", h, "k")
	if err != nil || !a.CheckLogin("admin", "a-long-enough-password") {
		t.Fatalf("hashed password login failed: %v", err)
	}
}

func TestSessionTokens(t *testing.T) {
	a, _ := NewAdmin("admin", "pw-pw-pw-pw-pw", "", "session-secret-A")
	tok, _, err := a.IssueSession()
	if err != nil {
		t.Fatal(err)
	}
	if u, err := a.VerifySession(tok); err != nil || u != "admin" {
		t.Errorf("valid session rejected: %v", err)
	}
	other, _ := NewAdmin("admin", "pw-pw-pw-pw-pw", "", "session-secret-B")
	if _, err := other.VerifySession(tok); err == nil {
		t.Error("session signed with another secret was accepted")
	}
	if _, err := a.VerifySession(tok + "x"); err == nil {
		t.Error("tampered session accepted")
	}
	a.TTL = -time.Minute
	expired, _, _ := a.IssueSession()
	if _, err := a.VerifySession(expired); err == nil {
		t.Error("expired session accepted")
	}
}
