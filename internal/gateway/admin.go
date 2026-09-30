package gateway

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"pnc3-gateway/internal/approval"
	"pnc3-gateway/internal/audit"
)

// Handler builds the full HTTP surface. ui may be nil (no dashboard).
func (g *Gateway) Handler(ui fs.FS) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", g.handleMCP)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"ok": true, "version": Version, "profile": g.cfg.Profile})
	})
	mux.Handle("GET /metrics", promhttp.HandlerFor(g.metrics.Registry, promhttp.HandlerOpts{}))

	admin := http.NewServeMux()
	admin.HandleFunc("GET /admin/state", g.adminState)
	admin.HandleFunc("GET /admin/decisions", g.adminDecisions)
	admin.HandleFunc("GET /admin/approvals", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, g.approvals.List()) })
	admin.HandleFunc("POST /admin/approvals/{id}", g.adminResolve)
	admin.HandleFunc("GET /admin/tools", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, g.registry.All()) })
	admin.HandleFunc("POST /admin/tools/refresh", func(w http.ResponseWriter, r *http.Request) {
		g.RefreshManifests(r.Context())
		writeJSON(w, g.registry.All())
	})
	admin.HandleFunc("POST /admin/tools/{name}/approve", g.adminApproveTool)
	admin.HandleFunc("GET /admin/policies", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, g.policy.Status()) })
	admin.HandleFunc("PUT /admin/policies/{file}", g.adminSavePolicy)
	admin.HandleFunc("GET /admin/agents", g.adminAgents)
	admin.HandleFunc("POST /admin/agents/{id}/revoke", g.adminRevoke)
	admin.HandleFunc("POST /admin/agents/{id}/restore", g.adminRestore)
	admin.HandleFunc("GET /admin/audit/verify", func(w http.ResponseWriter, _ *http.Request) {
		res, err := g.audit.Verify()
		if err != nil {
			writeHTTPError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, res)
	})
	admin.HandleFunc("GET /admin/bench", g.adminBench)
	admin.HandleFunc("GET /admin/ws", g.hub.serve)
	mux.Handle("/admin/", g.requireAdmin(admin))

	if ui != nil {
		mux.Handle("/", spa(ui))
	}
	return mux
}

func (g *Gateway) requireAdmin(next http.Handler) http.Handler {
	want := []byte(g.cfg.AdminToken)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := ""
		if h := r.Header.Get("Authorization"); strings.HasPrefix(strings.ToLower(h), "bearer ") {
			got = strings.TrimSpace(h[7:])
		} else if r.URL.Path == "/admin/ws" {
			got = r.URL.Query().Get("token") // browsers cannot set headers on WebSockets
		}
		if subtle.ConstantTimeCompare([]byte(got), want) != 1 {
			writeHTTPError(w, http.StatusUnauthorized, "admin token required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (g *Gateway) adminState(w http.ResponseWriter, r *http.Request) {
	revoked, _ := g.sessions.Revoked(r.Context())
	ps := g.policy.Status()
	writeJSON(w, map[string]any{
		"version": Version, "profile": g.cfg.Profile, "upstreams": g.upstreams.Status(),
		"audit_backend": g.audit.Backend(), "session_backend": g.sessions.Backend(),
		"audit_public_key": g.signer.PublicHex(), "policies_loaded": len(ps.Policies),
		"policy_error": ps.LastErr, "revoked_agents": revoked, "pending_approvals": len(g.approvals.List()),
	})
}

func (g *Gateway) adminDecisions(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	agent, verdict, typ := q.Get("agent"), q.Get("verdict"), q.Get("type")
	recs, err := g.audit.Recent(limit, func(rec *audit.Record) bool {
		return (agent == "" || rec.AgentID == agent) && (verdict == "" || rec.Verdict == verdict) && (typ == "" || rec.Type == typ)
	})
	if err != nil {
		writeHTTPError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if recs == nil {
		recs = []audit.Record{}
	}
	writeJSON(w, recs)
}

func (g *Gateway) adminResolve(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Outcome string `json:"outcome"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	outcome := map[string]string{"approve": approval.Approved, "approved": approval.Approved,
		"deny": approval.Denied, "denied": approval.Denied}[body.Outcome]
	if err := g.approvals.Resolve(r.PathValue("id"), outcome); err != nil {
		writeHTTPError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, map[string]string{"id": r.PathValue("id"), "outcome": outcome})
}

func (g *Gateway) adminApproveTool(w http.ResponseWriter, r *http.Request) {
	ev, err := g.registry.Approve(r.PathValue("name"))
	if err != nil {
		writeHTTPError(w, http.StatusBadRequest, err.Error())
		return
	}
	g.event("manifest", "", ev.Tool, ev.Kind, ev.Detail, nil)
	g.hub.Broadcast("tools", g.registry.All())
	writeJSON(w, ev)
}

func (g *Gateway) adminSavePolicy(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 256<<10))
	if err != nil {
		writeHTTPError(w, http.StatusBadRequest, err.Error())
		return
	}
	file := r.PathValue("file")
	if err := g.policy.Save(file, string(body)); err != nil {
		writeHTTPError(w, http.StatusBadRequest, err.Error())
		return
	}
	g.event("policy", "", "", "reloaded", "policy file saved: "+file, nil)
	writeJSON(w, g.policy.Status())
}

func (g *Gateway) adminAgents(w http.ResponseWriter, r *http.Request) {
	revoked, _ := g.sessions.Revoked(r.Context())
	isRevoked := map[string]bool{}
	for _, a := range revoked {
		isRevoked[a] = true
	}
	var out []map[string]any
	for _, a := range g.cfg.Agents {
		out = append(out, map[string]any{"id": a.ID, "owner": a.Owner, "allowed_tools": a.AllowedTools, "revoked": isRevoked[a.ID]})
	}
	writeJSON(w, out)
}

func (g *Gateway) adminRevoke(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := g.sessions.Revoke(r.Context(), id); err != nil {
		writeHTTPError(w, http.StatusInternalServerError, err.Error())
		return
	}
	g.approvals.DenyAgent(id)
	g.event("revocation", id, "", "revoked", "kill switch used", nil)
	writeJSON(w, map[string]any{"agent": id, "revoked": true})
}

func (g *Gateway) adminRestore(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := g.sessions.Restore(r.Context(), id); err != nil {
		writeHTTPError(w, http.StatusInternalServerError, err.Error())
		return
	}
	g.event("revocation", id, "", "restored", "agent restored", nil)
	writeJSON(w, map[string]any{"agent": id, "revoked": false})
}

func (g *Gateway) adminBench(w http.ResponseWriter, _ *http.Request) {
	b, err := os.ReadFile(filepath.Join(g.cfg.ResultsDir, "summary.json"))
	if err != nil {
		writeJSON(w, map[string]any{"available": false})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// spa serves the dashboard build, falling back to index.html for client routes.
func spa(ui fs.FS) http.Handler {
	files := http.FileServerFS(ui)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p != "" {
			if _, err := fs.Stat(ui, p); err == nil {
				files.ServeHTTP(w, r)
				return
			}
		}
		r2 := r.Clone(r.Context())
		r2.URL.Path = "/"
		files.ServeHTTP(w, r2)
	})
}
