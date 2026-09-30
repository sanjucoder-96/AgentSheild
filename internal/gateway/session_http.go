package gateway

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/time/rate"

	"pnc3-gateway/internal/auth"
)

// csrfHeader must accompany every state-changing request authenticated by the
// session cookie. Browsers will not send a custom header cross-site without a
// CORS preflight, and the gateway allows no cross-origin requests, so a
// malicious page cannot forge admin actions with the admin's cookie.
const csrfHeader = "X-Aegis-CSRF"

// requireAdmin accepts either the ADMIN_TOKEN bearer header (scripts, CI, demo)
// or a valid dashboard session cookie (people). Tokens in URLs are not accepted.
func (g *Gateway) requireAdmin(next http.Handler) http.Handler {
	want := []byte(g.cfg.AdminToken)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h := r.Header.Get("Authorization"); strings.HasPrefix(strings.ToLower(h), "bearer ") {
			if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(h[7:])), want) == 1 {
				next.ServeHTTP(w, r)
				return
			}
			writeHTTPError(w, http.StatusUnauthorized, "invalid admin token")
			return
		}
		if _, ok := g.sessionUser(r); ok {
			if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Header.Get(csrfHeader) != "1" {
				writeHTTPError(w, http.StatusForbidden, "missing CSRF header")
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		writeHTTPError(w, http.StatusUnauthorized, "login required")
	})
}

func (g *Gateway) sessionUser(r *http.Request) (string, bool) {
	if g.admin == nil {
		return "", false
	}
	c, err := r.Cookie(auth.SessionCookie)
	if err != nil || c.Value == "" {
		return "", false
	}
	user, err := g.admin.VerifySession(c.Value)
	return user, err == nil
}

func (g *Gateway) clientIP(r *http.Request) string {
	if g.cfg.TrustProxy {
		// Caddy appends the real client address as the last X-Forwarded-For entry.
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[len(parts)-1])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (g *Gateway) isHTTPS(r *http.Request) bool {
	return r.TLS != nil || (g.cfg.TrustProxy && r.Header.Get("X-Forwarded-Proto") == "https")
}

// 5 attempts per minute per client address, burst of 5.
func (g *Gateway) loginLimiter(ip string) *rate.Limiter {
	l, _ := g.loginLimits.LoadOrStore(ip, rate.NewLimiter(rate.Every(12*time.Second), 5))
	return l.(*rate.Limiter)
}

func (g *Gateway) handleLogin(w http.ResponseWriter, r *http.Request) {
	if g.admin == nil {
		writeHTTPError(w, http.StatusServiceUnavailable, "admin login is not configured")
		return
	}
	ip := g.clientIP(r)
	if !g.loginLimiter(ip).Allow() {
		g.event("auth", "", "", "login_throttled", "too many login attempts from "+ip, nil)
		writeHTTPError(w, http.StatusTooManyRequests, "too many attempts; wait a minute")
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&body); err != nil {
		writeHTTPError(w, http.StatusBadRequest, "username and password required")
		return
	}
	if !g.admin.CheckLogin(body.Username, body.Password) {
		g.event("auth", "", "", "login_failed", "failed dashboard login from "+ip, nil)
		writeHTTPError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}
	token, exp, err := g.admin.IssueSession()
	if err != nil {
		writeHTTPError(w, http.StatusInternalServerError, "could not create session")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: auth.SessionCookie, Value: token, Path: "/", Expires: exp,
		HttpOnly: true, Secure: g.isHTTPS(r), SameSite: http.SameSiteStrictMode,
	})
	g.event("auth", "", "", "login_ok", "dashboard login by "+body.Username+" from "+ip, nil)
	writeJSON(w, map[string]any{"user": body.Username, "expires": exp})
}

func (g *Gateway) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get(csrfHeader) != "1" {
		writeHTTPError(w, http.StatusForbidden, "missing CSRF header")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: auth.SessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: g.isHTTPS(r), SameSite: http.SameSiteStrictMode})
	writeJSON(w, map[string]bool{"ok": true})
}

func (g *Gateway) handleMe(w http.ResponseWriter, r *http.Request) {
	user, ok := g.sessionUser(r)
	if !ok {
		writeHTTPError(w, http.StatusUnauthorized, "not logged in")
		return
	}
	writeJSON(w, map[string]string{"user": user})
}
