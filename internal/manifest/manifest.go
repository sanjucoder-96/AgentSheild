// Package manifest pins every tool's name, description and input schema by
// SHA-256. If an upstream server silently changes any of them (a "rug pull"),
// the tool is quarantined: hidden from agents and refused, until an admin
// reviews the change and re-approves it.
package manifest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"pnc3-gateway/internal/config"
)

const (
	StatusActive       = "active"
	StatusQuarantined  = "quarantined"
	StatusUnregistered = "unregistered"
	StatusUnavailable  = "unavailable"
)

type UpstreamTool struct {
	Name        string
	Description string
	InputSchema any
}

type Tool struct {
	Name           string          `json:"name"`
	Server         string          `json:"server"`
	Description    string          `json:"description"`
	InputSchema    json.RawMessage `json:"input_schema"`
	Hash           string          `json:"hash"`
	PinnedHash     string          `json:"pinned_hash"`
	Status         string          `json:"status"`
	PendingDesc    string          `json:"pending_description,omitempty"`
	LastSeen       time.Time       `json:"last_seen"`
	Destructive    bool            `json:"destructive"`
	SendsExternal  bool            `json:"sends_external"`
	ReadsUntrusted bool            `json:"reads_untrusted"`
	ReadsPrivate   bool            `json:"reads_private"`

	schema        *jsonschema.Schema
	props         map[string]bool
	pendingSchema []byte
}

type Event struct {
	Tool   string `json:"tool"`
	Kind   string `json:"kind"` // pinned | quarantined | unregistered | unavailable | approved
	Detail string `json:"detail"`
}

type Registry struct {
	cfg     *config.Config
	pinFile string
	mu      sync.RWMutex
	tools   map[string]*Tool
	pins    map[string]string
}

func NewRegistry(cfg *config.Config) (*Registry, error) {
	r := &Registry{cfg: cfg, pinFile: filepath.Join(cfg.StateDir, "pins.json"),
		tools: map[string]*Tool{}, pins: map[string]string{}}
	if b, err := os.ReadFile(r.pinFile); err == nil {
		if err := json.Unmarshal(b, &r.pins); err != nil {
			return nil, fmt.Errorf("read pins: %w", err)
		}
	}
	return r, nil
}

// Hash is SHA-256 over canonical JSON of name, description and schema.
// Go marshals map keys in sorted order, so the encoding is stable.
func Hash(name, description string, schema any) string {
	var normalized any
	b, _ := json.Marshal(schema)
	_ = json.Unmarshal(b, &normalized)
	doc, _ := json.Marshal(map[string]any{"name": name, "description": description, "inputSchema": normalized})
	sum := sha256.Sum256(doc)
	return hex.EncodeToString(sum[:])
}

// Update reconciles a server's current tool list with the pins.
func (r *Registry) Update(server string, list []UpstreamTool) []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	var events []Event
	seen := map[string]bool{}
	for _, ut := range list {
		seen[ut.Name] = true
		schemaJSON, _ := json.Marshal(ut.InputSchema)
		h := Hash(ut.Name, ut.Description, ut.InputSchema)
		t := r.tools[ut.Name]
		if t == nil {
			t = &Tool{Name: ut.Name, Server: server}
			r.tools[ut.Name] = t
		}
		t.LastSeen = time.Now()
		t.Hash = h

		spec, registered := r.cfg.Tools[ut.Name]
		if !registered || spec.Server != server {
			if t.Status != StatusUnregistered {
				events = append(events, Event{ut.Name, "unregistered", "tool offered by " + server + " is not registered in the gateway config"})
			}
			t.Status, t.Server = StatusUnregistered, server
			continue
		}
		t.Destructive, t.SendsExternal = spec.Destructive, spec.SendsExternal
		t.ReadsUntrusted, t.ReadsPrivate = spec.ReadsUntrusted, spec.ReadsPrivate

		pinned, ok := r.pins[ut.Name]
		switch {
		case !ok:
			// Trust on first use: pin the manifest the first time we see it.
			r.pins[ut.Name] = h
			pinned = h
			r.activate(t, ut, schemaJSON)
			events = append(events, Event{ut.Name, "pinned", "manifest pinned " + h[:12]})
		case pinned == h:
			if t.Status != StatusActive || t.schema == nil {
				r.activate(t, ut, schemaJSON)
			}
		default:
			if t.Status != StatusQuarantined {
				events = append(events, Event{ut.Name, "quarantined",
					fmt.Sprintf("manifest changed: pinned %s, now %s", pinned[:12], h[:12])})
			}
			t.Status = StatusQuarantined
			t.PendingDesc = ut.Description
			t.pendingSchema = schemaJSON
		}
		t.PinnedHash = pinned
	}
	for name, t := range r.tools {
		if t.Server == server && !seen[name] && t.Status != StatusUnavailable {
			t.Status = StatusUnavailable
			events = append(events, Event{name, "unavailable", "no longer offered by " + server})
		}
	}
	if len(events) > 0 {
		r.savePins()
	}
	return events
}

func (r *Registry) activate(t *Tool, ut UpstreamTool, schemaJSON []byte) {
	t.Description = ut.Description
	t.InputSchema = schemaJSON
	t.PendingDesc = ""
	t.Status = StatusActive
	t.schema, t.props = compileSchema(ut.Name, schemaJSON)
}

// Approve accepts the current (changed) manifest after human review.
func (r *Registry) Approve(name string) (Event, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t := r.tools[name]
	if t == nil || t.Status != StatusQuarantined {
		return Event{}, fmt.Errorf("tool %s is not quarantined", name)
	}
	r.pins[name] = t.Hash
	t.PinnedHash = t.Hash
	t.Description = t.PendingDesc
	t.InputSchema = t.pendingSchema
	t.PendingDesc = ""
	t.Status = StatusActive
	t.schema, t.props = compileSchema(name, t.InputSchema)
	r.savePins()
	return Event{name, "approved", "new manifest approved " + t.Hash[:12]}, nil
}

func (r *Registry) Get(name string) *Tool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if t := r.tools[name]; t != nil {
		c := *t
		return &c
	}
	return nil
}

func (r *Registry) All() []Tool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Tool, 0, len(r.tools))
	for _, t := range r.tools {
		out = append(out, *t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ValidateArgs checks arguments against the pinned JSON Schema and, in strict
// mode, rejects argument names the schema does not declare (smuggled fields).
func (t *Tool) ValidateArgs(args map[string]any, strict bool) error {
	if strict {
		for k := range args {
			if !t.props[k] {
				return fmt.Errorf("argument %q is not declared in the tool schema", k)
			}
		}
	}
	if t.schema == nil {
		return fmt.Errorf("tool schema unavailable")
	}
	if err := t.schema.Validate(toSchemaValue(args)); err != nil {
		msg := err.Error()
		if i := strings.Index(msg, "\n"); i > 0 {
			msg = strings.TrimSpace(msg[i:])
		}
		return fmt.Errorf("%s", msg)
	}
	return nil
}

func compileSchema(name string, raw []byte) (*jsonschema.Schema, map[string]bool) {
	props := map[string]bool{}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, props
	}
	if m, ok := doc.(map[string]any); ok {
		if p, ok := m["properties"].(map[string]any); ok {
			for k := range p {
				props[k] = true
			}
		}
	}
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	url := "mem://tools/" + name + ".json"
	if err := c.AddResource(url, doc); err != nil {
		return nil, props
	}
	s, err := c.Compile(url)
	if err != nil {
		return nil, props
	}
	return s, props
}

// toSchemaValue round-trips through JSON so numbers are float64/json.Number as the validator expects.
func toSchemaValue(v any) any {
	b, _ := json.Marshal(v)
	out, _ := jsonschema.UnmarshalJSON(strings.NewReader(string(b)))
	return out
}

func (r *Registry) savePins() {
	_ = os.MkdirAll(filepath.Dir(r.pinFile), 0o755)
	b, _ := json.MarshalIndent(r.pins, "", "  ")
	_ = os.WriteFile(r.pinFile, b, 0o600)
}
