package auth

// Dashboard login for human administrators.
//
// The admin signs in with a username and password (bcrypt-checked). The
// gateway then sets a short-lived session cookie holding an HS256-signed
// token. The cookie is HttpOnly (JavaScript cannot read it), SameSite=Strict
// (other sites cannot send it) and Secure when served over HTTPS. Scripts and
// CI still use the ADMIN_TOKEN bearer header instead.

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const (
	SessionCookie   = "aegis_session"
	sessionIssuer   = "aegis-dashboard"
	sessionAudience = "aegis-admin"
)

// dummyHash keeps the login timing the same whether or not the username exists.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("timing-equaliser"), bcrypt.DefaultCost)

type Admin struct {
	username string
	hash     []byte
	secret   []byte
	TTL      time.Duration
}

// NewAdmin accepts either a bcrypt hash (optionally "b64:"-encoded, which keeps
// "$" characters out of .env files) or a plain password that is hashed now.
func NewAdmin(username, password, hash, sessionSecret string) (*Admin, error) {
	a := &Admin{username: username, secret: []byte(sessionSecret), TTL: 8 * time.Hour}
	switch {
	case hash != "":
		if strings.HasPrefix(hash, "b64:") {
			raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(hash, "b64:"))
			if err != nil {
				return nil, errors.New("ADMIN_PASSWORD_HASH: invalid base64")
			}
			hash = string(raw)
		}
		if _, err := bcrypt.Cost([]byte(hash)); err != nil {
			return nil, errors.New("ADMIN_PASSWORD_HASH is not a bcrypt hash")
		}
		a.hash = []byte(hash)
	case password != "":
		h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return nil, err
		}
		a.hash = h
	default:
		return nil, errors.New("no admin password configured")
	}
	return a, nil
}

// HashPassword returns a "b64:"-prefixed bcrypt hash for ADMIN_PASSWORD_HASH.
func HashPassword(password string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return "b64:" + base64.StdEncoding.EncodeToString(h), nil
}

// CheckLogin is constant-time with respect to whether the username matched.
func (a *Admin) CheckLogin(username, password string) bool {
	userOK := subtle.ConstantTimeCompare([]byte(username), []byte(a.username)) == 1
	hash := a.hash
	if !userOK {
		hash = dummyHash
	}
	passOK := bcrypt.CompareHashAndPassword(hash, []byte(password)) == nil
	return userOK && passOK
}

func (a *Admin) IssueSession() (string, time.Time, error) {
	exp := time.Now().Add(a.TTL)
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": sessionIssuer, "aud": sessionAudience, "sub": a.username,
		"iat": time.Now().Unix(), "exp": exp.Unix(),
	})
	s, err := t.SignedString(a.secret)
	return s, exp, err
}

// VerifySession returns the admin username for a valid, unexpired session token.
func (a *Admin) VerifySession(token string) (string, error) {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(*jwt.Token) (any, error) { return a.secret, nil },
		jwt.WithValidMethods([]string{"HS256"}), jwt.WithIssuer(sessionIssuer),
		jwt.WithAudience(sessionAudience), jwt.WithExpirationRequired())
	if err != nil {
		return "", err
	}
	sub, _ := claims["sub"].(string)
	if sub != a.username {
		return "", errors.New("session subject mismatch")
	}
	return sub, nil
}
