// Package upstream talks to the real tool servers using the official MCP Go SDK.
//
// The gateway is the only holder of the tool credential: it is added to every
// upstream HTTP request here, after a call has been allowed. Agents never see it.
package upstream

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"pnc3-gateway/internal/config"
)

type credentialTransport struct {
	secret string
	base   http.RoundTripper
}

// RoundTrip adds the gateway's tool credential to every upstream request.
func (t *credentialTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("X-Gateway-Credential", t.secret)
	return t.base.RoundTrip(r)
}

// Pool keeps one MCP client session per upstream tool server.
type Pool struct {
	cfg      *config.Config
	client   *mcp.Client
	http     *http.Client
	mu       sync.Mutex
	sessions map[string]*mcp.ClientSession
	status   map[string]string
}

// NewPool returns a pool whose HTTP client injects the tool credential.
func NewPool(cfg *config.Config, version string) *Pool {
	return &Pool{
		cfg:    cfg,
		client: mcp.NewClient(&mcp.Implementation{Name: "pnc3-secure-agent-gateway", Version: version}, nil),
		http: &http.Client{
			Transport: &credentialTransport{secret: cfg.ToolSharedSecret, base: http.DefaultTransport},
			Timeout:   cfg.ToolTimeout.Duration + 5*time.Second,
		},
		sessions: map[string]*mcp.ClientSession{},
		status:   map[string]string{},
	}
}

func (p *Pool) upstream(name string) (config.Upstream, bool) {
	for _, u := range p.cfg.Upstreams {
		if u.Name == name {
			return u, true
		}
	}
	return config.Upstream{}, false
}

func (p *Pool) session(ctx context.Context, name string) (*mcp.ClientSession, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if s := p.sessions[name]; s != nil {
		return s, nil
	}
	u, ok := p.upstream(name)
	if !ok {
		return nil, fmt.Errorf("unknown upstream %s", name)
	}
	t := &mcp.StreamableClientTransport{Endpoint: u.URL, HTTPClient: p.http, DisableStandaloneSSE: true, MaxRetries: -1}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	s, err := p.client.Connect(cctx, t, nil)
	if err != nil {
		p.status[name] = "down: " + err.Error()
		return nil, err
	}
	p.sessions[name] = s
	p.status[name] = "up"
	return s, nil
}

func (p *Pool) drop(name string, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if s := p.sessions[name]; s != nil {
		_ = s.Close()
	}
	delete(p.sessions, name)
	p.status[name] = "down: " + err.Error()
}

// ListTools returns the tools an upstream server currently offers.
func (p *Pool) ListTools(ctx context.Context, name string) ([]*mcp.Tool, error) {
	s, err := p.session(ctx, name)
	if err != nil {
		return nil, err
	}
	res, err := s.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		p.drop(name, err)
		return nil, err
	}
	return res.Tools, nil
}

// CallTool forwards an allowed call to its tool server, within the configured timeout.
func (p *Pool) CallTool(ctx context.Context, server, tool string, args map[string]any) (*mcp.CallToolResult, error) {
	s, err := p.session(ctx, server)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, p.cfg.ToolTimeout.Duration)
	defer cancel()
	res, err := s.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		p.drop(server, err)
		return nil, err
	}
	return res, nil
}

// Status reports whether each upstream is connected.
func (p *Pool) Status() map[string]string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := map[string]string{}
	for _, u := range p.cfg.Upstreams {
		st := p.status[u.Name]
		if st == "" {
			st = "not connected"
		}
		out[u.Name] = st
	}
	return out
}
