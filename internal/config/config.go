// Package config loads the gateway configuration from YAML plus environment
// variables. Secrets never live in the YAML file; they come from the environment.
package config

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Profiles control how much of the pipeline runs. "off" and "allowlist_only"
// exist so the benchmark can compare the full gateway against baselines.
const (
	ProfileFull          = "full"
	ProfileAllowlistOnly = "allowlist_only"
	ProfileOff           = "off"
)

// Argument kinds the inspector understands.
const (
	KindEmail   = "email"
	KindURL     = "url"
	KindPath    = "path"
	KindCommand = "command"
	KindSQL     = "sql"
)

// Duration is a time.Duration that can be written as "10s" in YAML.
type Duration struct{ time.Duration }

// UnmarshalYAML parses a duration string such as "60s".
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	v, err := time.ParseDuration(n.Value)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", n.Value, err)
	}
	d.Duration = v
	return nil
}

// Config is the complete gateway configuration: YAML settings plus secrets from the environment.
type Config struct {
	Listen             string          `yaml:"listen"`
	Profile            string          `yaml:"profile"`
	StateDir           string          `yaml:"state_dir"`
	PolicyDir          string          `yaml:"policy_dir"`
	ResultsDir         string          `yaml:"results_dir"`
	MaxBodyBytes       int64           `yaml:"max_body_bytes"`
	MaxJSONDepth       int             `yaml:"max_json_depth"`
	MaxDecodeDepth     int             `yaml:"max_decode_depth"`
	ApprovalTimeout    Duration        `yaml:"approval_timeout"`
	ToolTimeout        Duration        `yaml:"tool_timeout"`
	ManifestRefresh    Duration        `yaml:"manifest_refresh"`
	RateLimitPerMinute int             `yaml:"rate_limit_per_minute"`
	Auth               Auth            `yaml:"auth"`
	Upstreams          []Upstream      `yaml:"upstreams"`
	Agents             []Agent         `yaml:"agents"`
	Destinations       Destinations    `yaml:"destinations"`
	Tools              map[string]Tool `yaml:"tools"`

	// From the environment only.
	JWTSecret        string `yaml:"-"`
	AdminToken       string `yaml:"-"`
	ToolSharedSecret string `yaml:"-"`
	DatabaseURL      string `yaml:"-"`
	RedisURL         string `yaml:"-"`
	ModelEndpoint    string `yaml:"-"`
	Env              string `yaml:"-"` // "production" enables the startup secret guard
	AdminUsername    string `yaml:"-"`
	AdminPassword    string `yaml:"-"` // plain (hashed in memory at start) ...
	AdminPassHash    string `yaml:"-"` // ... or a bcrypt hash ("b64:" prefix allowed)
	SessionSecret    string `yaml:"-"`
	TrustProxy       bool   `yaml:"-"` // behind Caddy: trust X-Forwarded-For / -Proto
	ModelAPIKey      string `yaml:"-"`
	ModelName        string `yaml:"-"`
}

// Auth selects how agents authenticate: dev tokens or an OIDC provider.
type Auth struct {
	Mode         string `yaml:"mode"` // "dev" (HS256 tokens from gatewayctl) or "oidc" (e.g. Keycloak)
	OIDCIssuer   string `yaml:"oidc_issuer"`
	OIDCAudience string `yaml:"oidc_audience"`
	AgentClaim   string `yaml:"agent_claim"`
}

// Upstream is a tool server that allowed calls are forwarded to.
type Upstream struct {
	Name string `yaml:"name"`
	URL  string `yaml:"url"`
}

// Agent is a registered AI agent and the tools it may call.
type Agent struct {
	ID           string   `yaml:"id"`
	Owner        string   `yaml:"owner"`
	AllowedTools []string `yaml:"allowed_tools"`
}

// Destinations lists where data may go: allowed email domains, web hosts and internal hosts.
type Destinations struct {
	EmailDomains  []string          `yaml:"email_domains"`
	URLHosts      []string          `yaml:"url_hosts"`
	InternalHosts []string          `yaml:"internal_hosts"`
	StaticDNS     map[string]string `yaml:"static_dns"`
}

// Tool describes a registered tool: its server, risk flags, and which arguments carry destinations, paths, commands or SQL.
type Tool struct {
	Server          string            `yaml:"server"`
	AllowedAgents   []string          `yaml:"allowed_agents"`
	MaxArgsBytes    int64             `yaml:"max_args_bytes"`
	RequireApproval bool              `yaml:"require_approval"`
	Destructive     bool              `yaml:"destructive"`
	SendsExternal   bool              `yaml:"sends_external"`
	ReadsUntrusted  bool              `yaml:"reads_untrusted"`
	ReadsPrivate    bool              `yaml:"reads_private"`
	Args            map[string]string `yaml:"args"`
}

// Load reads the YAML file, applies environment overrides and defaults, and validates the result.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := &Config{}
	if err := yaml.Unmarshal(raw, c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	c.applyEnv()
	c.applyDefaults()
	return c, c.validate()
}

func (c *Config) applyEnv() {
	if v := os.Getenv("GATEWAY_PROFILE"); v != "" {
		c.Profile = v
	}
	if v := os.Getenv("GATEWAY_LISTEN"); v != "" {
		c.Listen = v
	}
	if v := os.Getenv("GATEWAY_STATE_DIR"); v != "" {
		c.StateDir = v
	}
	c.JWTSecret = envOr("GATEWAY_JWT_SECRET", "dev-jwt-secret-change-me")
	c.AdminToken = envOr("ADMIN_TOKEN", "dev-admin-token")
	c.ToolSharedSecret = envOr("TOOL_SHARED_SECRET", "dev-tool-secret-change-me")
	c.DatabaseURL = os.Getenv("DATABASE_URL")
	c.RedisURL = os.Getenv("REDIS_URL")
	c.Env = strings.ToLower(os.Getenv("GATEWAY_ENV"))
	c.AdminUsername = envOr("ADMIN_USERNAME", "admin")
	c.AdminPassword = os.Getenv("ADMIN_PASSWORD")
	c.AdminPassHash = os.Getenv("ADMIN_PASSWORD_HASH")
	c.SessionSecret = envOr("SESSION_SECRET", "dev-session-secret-change-me")
	c.TrustProxy = os.Getenv("TRUST_PROXY") == "true"
	if c.AdminPassword == "" && c.AdminPassHash == "" && c.Env != "production" {
		c.AdminPassword = "admin" // local development only; production refuses to start without one
	}
	c.ModelEndpoint = envOr("MODEL_ENDPOINT", "https://api.groq.com/openai/v1/chat/completions")
	c.ModelAPIKey = os.Getenv("MODEL_API_KEY")
	c.ModelName = envOr("MODEL_NAME", "openai/gpt-oss-20b")
}

func (c *Config) applyDefaults() {
	def := func(s *string, v string) {
		if *s == "" {
			*s = v
		}
	}
	def(&c.Listen, ":8080")
	def(&c.Profile, ProfileFull)
	def(&c.StateDir, "state")
	def(&c.PolicyDir, "config/policies")
	def(&c.ResultsDir, "results")
	def(&c.Auth.Mode, "dev")
	def(&c.Auth.AgentClaim, "agent")
	if c.MaxBodyBytes == 0 {
		c.MaxBodyBytes = 1 << 20
	}
	if c.MaxJSONDepth == 0 {
		c.MaxJSONDepth = 32
	}
	if c.MaxDecodeDepth == 0 {
		c.MaxDecodeDepth = 4
	}
	if c.ApprovalTimeout.Duration == 0 {
		c.ApprovalTimeout.Duration = 60 * time.Second
	}
	if c.ToolTimeout.Duration == 0 {
		c.ToolTimeout.Duration = 10 * time.Second
	}
	if c.ManifestRefresh.Duration == 0 {
		c.ManifestRefresh.Duration = 10 * time.Second
	}
	if c.RateLimitPerMinute == 0 {
		c.RateLimitPerMinute = 600
	}
	for name, tool := range c.Tools {
		if tool.MaxArgsBytes == 0 {
			tool.MaxArgsBytes = 64 << 10
		}
		c.Tools[name] = tool
	}
}

// ProductionProblems lists unsafe settings. In production the gateway refuses
// to start while any of these remain, so a forgotten default secret can never
// reach a public server.
func (c *Config) ProductionProblems() []string {
	var out []string
	weak := func(name, v string) {
		if strings.HasPrefix(v, "dev-") || len(v) < 32 {
			out = append(out, name+" must be a random value of at least 32 characters")
		}
	}
	weak("GATEWAY_JWT_SECRET", c.JWTSecret)
	weak("ADMIN_TOKEN", c.AdminToken)
	weak("TOOL_SHARED_SECRET", c.ToolSharedSecret)
	weak("SESSION_SECRET", c.SessionSecret)
	if c.AdminPassHash == "" && len(c.AdminPassword) < 12 {
		out = append(out, "ADMIN_PASSWORD (12+ characters) or ADMIN_PASSWORD_HASH is required")
	}
	if c.AdminPassword == "admin" {
		out = append(out, "ADMIN_PASSWORD must not be the development default")
	}
	return out
}

func (c *Config) validate() error {
	if c.Env == "production" {
		if p := c.ProductionProblems(); len(p) > 0 {
			return fmt.Errorf("refusing to start in production with unsafe settings:\n  - %s", strings.Join(p, "\n  - "))
		}
	}
	switch c.Profile {
	case ProfileFull, ProfileAllowlistOnly, ProfileOff:
	default:
		return fmt.Errorf("unknown profile %q", c.Profile)
	}
	servers := map[string]bool{}
	for _, u := range c.Upstreams {
		servers[u.Name] = true
	}
	for name, t := range c.Tools {
		if !servers[t.Server] {
			return fmt.Errorf("tool %s refers to unknown upstream %q", name, t.Server)
		}
		for arg, kind := range t.Args {
			switch kind {
			case KindEmail, KindURL, KindPath, KindCommand, KindSQL:
			default:
				return fmt.Errorf("tool %s arg %s: unknown kind %q", name, arg, kind)
			}
		}
	}
	return nil
}

// Agent looks up a registered agent by id.
func (c *Config) Agent(id string) (Agent, bool) {
	for _, a := range c.Agents {
		if a.ID == id {
			return a, true
		}
	}
	return Agent{}, false
}

// AgentAllows reports whether the agent may call the tool.
func (c *Config) AgentAllows(agentID, tool string) bool {
	a, ok := c.Agent(agentID)
	if !ok {
		return false
	}
	for _, t := range a.AllowedTools {
		if t == tool {
			return true
		}
	}
	return false
}

// ToolNames returns the registered tool names in sorted order.
func (c *Config) ToolNames() []string {
	out := make([]string, 0, len(c.Tools))
	for n := range c.Tools {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// HostAllowed matches exact hosts and "*.domain" wildcards (which also match the bare domain).
func HostAllowed(host string, patterns []string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, p := range patterns {
		p = strings.ToLower(p)
		if strings.HasPrefix(p, "*.") {
			base := p[2:]
			if host == base || strings.HasSuffix(host, "."+base) {
				return true
			}
		} else if host == p {
			return true
		}
	}
	return false
}

func envOr(k, v string) string {
	if s := os.Getenv(k); s != "" {
		return s
	}
	return v
}
