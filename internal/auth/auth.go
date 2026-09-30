// Package auth identifies the agent behind each request.
//
// "dev" mode: short-lived HS256 tokens minted by `gatewayctl token`.
// "oidc" mode: tokens from an OIDC provider such as Keycloak, verified against
// the issuer's published keys. The agent id is read from a configurable claim.
package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"

	"pnc3-gateway/internal/config"
)

const devIssuer = "pnc3-gateway-dev"

type Identity struct {
	AgentID string
	Subject string
}

type Verifier interface {
	Verify(ctx context.Context, bearer string) (Identity, error)
}

func New(ctx context.Context, cfg *config.Config) (Verifier, error) {
	switch cfg.Auth.Mode {
	case "dev":
		return &devVerifier{secret: []byte(cfg.JWTSecret)}, nil
	case "oidc":
		p, err := oidc.NewProvider(ctx, cfg.Auth.OIDCIssuer)
		if err != nil {
			return nil, fmt.Errorf("oidc provider: %w", err)
		}
		v := p.Verifier(&oidc.Config{ClientID: cfg.Auth.OIDCAudience, SkipClientIDCheck: cfg.Auth.OIDCAudience == ""})
		return &oidcVerifier{v: v, claim: cfg.Auth.AgentClaim}, nil
	default:
		return nil, fmt.Errorf("unknown auth mode %q", cfg.Auth.Mode)
	}
}

func BearerToken(header string) (string, error) {
	const p = "bearer "
	if len(header) < len(p) || !strings.EqualFold(header[:len(p)], p) {
		return "", errors.New("missing bearer token")
	}
	return strings.TrimSpace(header[len(p):]), nil
}

type devVerifier struct{ secret []byte }

func (d *devVerifier) Verify(_ context.Context, token string) (Identity, error) {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) { return d.secret, nil },
		jwt.WithValidMethods([]string{"HS256"}), jwt.WithIssuer(devIssuer), jwt.WithExpirationRequired())
	if err != nil {
		return Identity{}, err
	}
	agent, _ := claims["agent"].(string)
	sub, _ := claims["sub"].(string)
	if agent == "" {
		return Identity{}, errors.New("token has no agent claim")
	}
	return Identity{AgentID: agent, Subject: sub}, nil
}

// IssueDevToken mints a token for local development and demos.
func IssueDevToken(secret, agent, subject string, ttl time.Duration) (string, error) {
	now := time.Now()
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": devIssuer, "sub": subject, "agent": agent,
		"iat": now.Unix(), "exp": now.Add(ttl).Unix(),
	})
	return t.SignedString([]byte(secret))
}

type oidcVerifier struct {
	v     *oidc.IDTokenVerifier
	claim string
}

func (o *oidcVerifier) Verify(ctx context.Context, token string) (Identity, error) {
	idt, err := o.v.Verify(ctx, token)
	if err != nil {
		return Identity{}, err
	}
	var claims map[string]any
	if err := idt.Claims(&claims); err != nil {
		return Identity{}, err
	}
	for _, k := range []string{o.claim, "azp", "client_id"} {
		if s, ok := claims[k].(string); ok && s != "" {
			return Identity{AgentID: s, Subject: idt.Subject}, nil
		}
	}
	return Identity{}, errors.New("token has no agent identifier claim")
}
