// Package policy wraps cedar-go.
//
// Cedar returns only Allow or Deny. The gateway adds a third outcome with an
// annotation: if the decision is Allow and any policy that produced it carries
// @approval("required"), the call is held for a human. Because a forbid always
// beats a permit in Cedar, an approval rule can never unblock a denied call.
//
// Fail closed: if any policy errors during evaluation, the call is denied.
// (Plain Cedar would skip an erroring forbid, which would silently allow.)
package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cedar-policy/cedar-go"
	"github.com/fsnotify/fsnotify"
)

const (
	VerdictAllow    = "allow"
	VerdictDeny     = "deny"
	VerdictApproval = "approval"
)

type Meta struct {
	ID       string `json:"id"`
	Effect   string `json:"effect"`
	Approval bool   `json:"approval"`
	Reason   string `json:"reason"`
	File     string `json:"file"`
}

type Decision struct {
	Verdict string   `json:"verdict"`
	RuleIDs []string `json:"rule_ids"`
	Reason  string   `json:"reason"`
	Errors  []string `json:"errors,omitempty"`
}

type Engine struct {
	dir      string
	mu       sync.RWMutex
	set      *cedar.PolicySet
	meta     map[cedar.PolicyID]Meta
	files    map[string]string
	loadedAt time.Time
	lastErr  error
	onReload func(err error)
}

func NewEngine(dir string) (*Engine, error) {
	e := &Engine{dir: dir}
	if err := e.Reload(); err != nil {
		return nil, err
	}
	return e, nil
}

// Reload parses every *.cedar file. On error the previous policy set stays active.
func (e *Engine) Reload() error {
	files, err := readDir(e.dir)
	if err == nil {
		var set *cedar.PolicySet
		var meta map[cedar.PolicyID]Meta
		set, meta, err = compile(files)
		if err == nil {
			e.mu.Lock()
			e.set, e.meta, e.files, e.loadedAt, e.lastErr = set, meta, files, time.Now(), nil
			e.mu.Unlock()
			return nil
		}
	}
	e.mu.Lock()
	e.lastErr = err
	e.mu.Unlock()
	return err
}

func readDir(dir string) (map[string]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	files := map[string]string{}
	for _, en := range entries {
		if en.IsDir() || !strings.HasSuffix(en.Name(), ".cedar") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, en.Name()))
		if err != nil {
			return nil, err
		}
		files[en.Name()] = string(b)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no .cedar files in %s", dir)
	}
	return files, nil
}

func compile(files map[string]string) (*cedar.PolicySet, map[cedar.PolicyID]Meta, error) {
	set := cedar.NewPolicySet()
	meta := map[cedar.PolicyID]Meta{}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		list, err := cedar.NewPolicyListFromBytes(name, []byte(files[name]))
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", name, err)
		}
		for i, p := range list {
			ann := p.Annotations()
			id := string(ann["id"])
			if id == "" {
				id = fmt.Sprintf("%s#%d", name, i)
			}
			pid := cedar.PolicyID(id)
			if _, dup := meta[pid]; dup {
				return nil, nil, fmt.Errorf("%s: duplicate policy id %q", name, id)
			}
			effect := "forbid"
			if p.Effect() == cedar.Permit {
				effect = "permit"
			}
			set.Add(pid, p)
			meta[pid] = Meta{
				ID: id, Effect: effect, File: name,
				Approval: string(ann["approval"]) == "required",
				Reason:   string(ann["reason"]),
			}
		}
	}
	return set, meta, nil
}

// Validate checks a candidate file without activating it.
func (e *Engine) Validate(name, text string) error {
	e.mu.RLock()
	files := map[string]string{}
	for k, v := range e.files {
		files[k] = v
	}
	e.mu.RUnlock()
	files[name] = text
	_, _, err := compile(files)
	return err
}

// Save validates then writes a policy file; the watcher (or caller) reloads it.
func (e *Engine) Save(name, text string) error {
	if !strings.HasSuffix(name, ".cedar") || strings.ContainsAny(name, `/\`) || strings.HasPrefix(name, ".") {
		return fmt.Errorf("invalid policy file name")
	}
	if err := e.Validate(name, text); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(e.dir, name), []byte(text), 0o644); err != nil {
		return err
	}
	return e.Reload()
}

// Delete removes one complete policy file only when the remaining set still
// compiles. The active policy set is left untouched on any failure.
func (e *Engine) Delete(name string) error {
	if !strings.HasSuffix(name, ".cedar") || strings.ContainsAny(name, `/\`) || strings.HasPrefix(name, ".") {
		return fmt.Errorf("invalid policy file name")
	}
	e.mu.RLock()
	if _, exists := e.files[name]; !exists {
		e.mu.RUnlock()
		return fmt.Errorf("policy file %q does not exist", name)
	}
	files := map[string]string{}
	for k, v := range e.files {
		if k != name {
			files[k] = v
		}
	}
	e.mu.RUnlock()
	if len(files) == 0 {
		return fmt.Errorf("at least one policy file must remain")
	}
	if _, _, err := compile(files); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(e.dir, name)); err != nil {
		return err
	}
	return e.Reload()
}

func (e *Engine) Decide(entities cedar.EntityMap, req cedar.Request) Decision {
	e.mu.RLock()
	set, meta := e.set, e.meta
	e.mu.RUnlock()

	ok, diag := set.IsAuthorized(entities, req)
	d := Decision{}
	if len(diag.Errors) > 0 {
		d.Verdict = VerdictDeny
		d.Reason = "policy_evaluation_error"
		for _, er := range diag.Errors {
			d.Errors = append(d.Errors, er.String())
			d.RuleIDs = append(d.RuleIDs, string(er.PolicyID))
		}
		return d
	}
	for _, r := range diag.Reasons {
		d.RuleIDs = append(d.RuleIDs, string(r.PolicyID))
	}
	sort.Strings(d.RuleIDs)
	if !ok {
		d.Verdict = VerdictDeny
		if len(d.RuleIDs) == 0 {
			d.Reason = "no_permit_matched"
			d.RuleIDs = []string{"default-deny"}
			return d
		}
		d.Reason = d.RuleIDs[0]
		return d
	}
	d.Verdict = VerdictAllow
	d.Reason = "permitted"
	for _, id := range d.RuleIDs {
		if meta[cedar.PolicyID(id)].Approval {
			d.Verdict = VerdictApproval
			d.Reason = id
		}
	}
	return d
}

// ReasonText returns the human-readable @reason of a rule, if any.
func (e *Engine) ReasonText(id string) string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.meta[cedar.PolicyID(id)].Reason
}

type Status struct {
	Files    map[string]string `json:"files"`
	Policies []Meta            `json:"policies"`
	LoadedAt time.Time         `json:"loaded_at"`
	LastErr  string            `json:"last_error,omitempty"`
}

func (e *Engine) Status() Status {
	e.mu.RLock()
	defer e.mu.RUnlock()
	s := Status{Files: e.files, LoadedAt: e.loadedAt}
	for _, m := range e.meta {
		s.Policies = append(s.Policies, m)
	}
	sort.Slice(s.Policies, func(i, j int) bool {
		if s.Policies[i].File != s.Policies[j].File {
			return s.Policies[i].File < s.Policies[j].File
		}
		return s.Policies[i].ID < s.Policies[j].ID
	})
	if e.lastErr != nil {
		s.LastErr = e.lastErr.Error()
	}
	return s
}

// Watch hot-reloads policies when files change on disk.
func (e *Engine) Watch(onReload func(error)) error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	if err := w.Add(e.dir); err != nil {
		return err
	}
	go func() {
		var timer *time.Timer
		for {
			select {
			case ev, ok := <-w.Events:
				if !ok {
					return
				}
				if !strings.HasSuffix(ev.Name, ".cedar") {
					continue
				}
				if timer != nil {
					timer.Stop()
				}
				timer = time.AfterFunc(200*time.Millisecond, func() { onReload(e.Reload()) })
			case _, ok := <-w.Errors:
				if !ok {
					return
				}
			}
		}
	}()
	return nil
}
