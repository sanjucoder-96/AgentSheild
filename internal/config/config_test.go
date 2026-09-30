package config

import "testing"

func TestProductionGuardRejectsDefaults(t *testing.T) {
	c := &Config{JWTSecret: "dev-jwt-secret-change-me", AdminToken: "dev-admin-token",
		ToolSharedSecret: "short", SessionSecret: "dev-session-secret-change-me", AdminPassword: "admin"}
	if got := len(c.ProductionProblems()); got < 5 {
		t.Errorf("expected every unsafe default to be reported, got %d problems", got)
	}
}

func TestProductionGuardAcceptsStrongSettings(t *testing.T) {
	strong := "0123456789abcdef0123456789abcdef"
	c := &Config{JWTSecret: strong, AdminToken: strong, ToolSharedSecret: strong, SessionSecret: strong,
		AdminPassword: "a-strong-admin-password"}
	if p := c.ProductionProblems(); len(p) != 0 {
		t.Errorf("strong settings flagged: %v", p)
	}
}
