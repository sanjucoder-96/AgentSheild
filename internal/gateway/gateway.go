// Package gateway is the zero-trust proxy between AI agents and their tools.
package gateway

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"pnc3-gateway/internal/approval"
	"pnc3-gateway/internal/audit"
	"pnc3-gateway/internal/auth"
	"pnc3-gateway/internal/config"
	"pnc3-gateway/internal/inspect"
	"pnc3-gateway/internal/manifest"
	"pnc3-gateway/internal/policy"
	"pnc3-gateway/internal/session"
	"pnc3-gateway/internal/upstream"
)

const Version = "0.1.0-mvp"

// Gateway is the zero-trust proxy: it authenticates, inspects and decides every tool call, then executes allowed ones.
type Gateway struct {
	cfg       *config.Config
	log       *slog.Logger
	auth      auth.Verifier
	policy    *policy.Engine
	registry  *manifest.Registry
	upstreams *upstream.Pool
	sessions  session.Store
	audit     audit.Store
	signer    *audit.Signer
	approvals *approval.Broker
	inspector *inspect.Inspector
	hub       *Hub
	metrics   *Metrics

	admin       *auth.Admin
	loginLimits sync.Map // client ip -> *rate.Limiter
	mcpSessions sync.Map // session id -> agent id
	limiters    sync.Map // agent id -> *rate.Limiter
	lastRefresh time.Time
	refreshMu   sync.Mutex
}

// Deps are the components a Gateway is built from.
type Deps struct {
	Config    *config.Config
	Logger    *slog.Logger
	Auth      auth.Verifier
	Policy    *policy.Engine
	Registry  *manifest.Registry
	Upstreams *upstream.Pool
	Sessions  session.Store
	Audit     audit.Store
	Signer    *audit.Signer
	Admin     *auth.Admin
}

// New wires the gateway together from its dependencies.
func New(d Deps) *Gateway {
	g := &Gateway{
		cfg: d.Config, log: d.Logger, auth: d.Auth, policy: d.Policy, registry: d.Registry,
		upstreams: d.Upstreams, sessions: d.Sessions, audit: d.Audit, signer: d.Signer, admin: d.Admin,
		approvals: approval.NewBroker(), inspector: inspect.New(d.Config), hub: NewHub(), metrics: NewMetrics(),
	}
	g.approvals.OnChange = func() { g.hub.Broadcast("approvals", g.approvals.List()) }
	return g
}

// Start launches the manifest refresh loop.
func (g *Gateway) Start(ctx context.Context) {
	g.RefreshManifests(ctx)
	go func() {
		t := time.NewTicker(g.cfg.ManifestRefresh.Duration)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				g.RefreshManifests(ctx)
			}
		}
	}()
}

// RefreshManifests re-reads every upstream's tool list and reconciles pins.
func (g *Gateway) RefreshManifests(ctx context.Context) {
	g.refreshMu.Lock()
	defer g.refreshMu.Unlock()
	g.lastRefresh = time.Now()
	for _, u := range g.cfg.Upstreams {
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		tools, err := g.upstreams.ListTools(cctx, u.Name)
		cancel()
		if err != nil {
			g.log.Warn("upstream unavailable", "upstream", u.Name, "err", err)
			continue
		}
		list := make([]manifest.UpstreamTool, 0, len(tools))
		for _, t := range tools {
			list = append(list, manifest.UpstreamTool{Name: t.Name, Description: t.Description, InputSchema: t.InputSchema})
		}
		for _, ev := range g.registry.Update(u.Name, list) {
			g.log.Info("manifest event", "tool", ev.Tool, "kind", ev.Kind, "detail", ev.Detail)
			g.event("manifest", "", ev.Tool, ev.Kind, ev.Detail, nil)
		}
	}
	g.hub.Broadcast("tools", g.registry.All())
}

func (g *Gateway) refreshIfStale(ctx context.Context, maxAge time.Duration) {
	g.refreshMu.Lock()
	stale := time.Since(g.lastRefresh) > maxAge
	g.refreshMu.Unlock()
	if stale {
		g.RefreshManifests(ctx)
	}
}

// event writes a non-decision audit record and pushes it to the dashboard.
func (g *Gateway) event(typ, agent, tool, verdict, reason string, detail any) {
	rec := &audit.Record{ID: audit.NewID("evt"), Type: typ, AgentID: agent, Tool: tool, Verdict: verdict, Reason: reason}
	if detail != nil {
		rec.Detail, _ = json.Marshal(detail)
	}
	if err := g.audit.Append(rec); err != nil {
		g.log.Error("audit append failed", "err", err)
	}
	g.hub.Broadcast("event", rec)
}

func (g *Gateway) limiter(agent string) *rate.Limiter {
	if l, ok := g.limiters.Load(agent); ok {
		return l.(*rate.Limiter)
	}
	per := g.cfg.RateLimitPerMinute
	burst := per / 10
	if burst < 10 {
		burst = 10
	}
	l, _ := g.limiters.LoadOrStore(agent, rate.NewLimiter(rate.Every(time.Minute/time.Duration(per)), burst))
	return l.(*rate.Limiter)
}

// PolicyReloaded records a hot reload (or a rejected one) and tells dashboards.
func (g *Gateway) PolicyReloaded(err error) {
	if err != nil {
		g.event("policy", "", "", "rejected", "policy change rejected: "+err.Error(), nil)
	} else {
		g.event("policy", "", "", "reloaded", "policies reloaded from disk", nil)
	}
	g.hub.Broadcast("policies", g.policy.Status())
	g.hub.Broadcast("tools", g.registry.All())
}
