// Package approval holds calls that need a human decision.
// The agent's request waits until someone approves or denies it in the
// dashboard. If nobody answers before the timeout, the call is denied.
package approval

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"
)

const (
	Approved  = "approved"
	Denied    = "denied"
	TimedOut  = "timeout"
	Cancelled = "cancelled"
)

// Pending is a tool call held for a human decision, as shown in the approval queue.
type Pending struct {
	ID         string          `json:"id"`
	DecisionID string          `json:"decision_id"`
	AgentID    string          `json:"agent_id"`
	SessionID  string          `json:"session_id"`
	Tool       string          `json:"tool"`
	Args       json.RawMessage `json:"args"`
	RuleIDs    []string        `json:"rule_ids"`
	Reason     string          `json:"reason"`
	Findings   []string        `json:"findings"`
	Created    time.Time       `json:"created"`
	Expires    time.Time       `json:"expires"`
	ch         chan string
}

// Broker holds pending approvals and delivers each human decision to the waiting request.
type Broker struct {
	mu       sync.Mutex
	pending  map[string]*Pending
	OnChange func()
}

// NewBroker returns an empty approval broker.
func NewBroker() *Broker { return &Broker{pending: map[string]*Pending{}} }

// Wait registers the call and blocks until an outcome is known.
func (b *Broker) Wait(ctx context.Context, p *Pending, wait time.Duration) string {
	if wait <= 0 {
		return TimedOut
	}
	p.ch = make(chan string, 1)
	p.Created = time.Now()
	p.Expires = p.Created.Add(wait)
	b.mu.Lock()
	b.pending[p.ID] = p
	b.mu.Unlock()
	b.changed()
	defer func() {
		b.mu.Lock()
		delete(b.pending, p.ID)
		b.mu.Unlock()
		b.changed()
	}()
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case out := <-p.ch:
		return out
	case <-timer.C:
		return TimedOut
	case <-ctx.Done():
		return Cancelled
	}
}

// Resolve records a human decision (approved or denied) and wakes the waiting request.
func (b *Broker) Resolve(id, outcome string) error {
	if outcome != Approved && outcome != Denied {
		return fmt.Errorf("outcome must be approved or denied")
	}
	b.mu.Lock()
	p := b.pending[id]
	b.mu.Unlock()
	if p == nil {
		return fmt.Errorf("no pending approval %s (it may have timed out)", id)
	}
	select {
	case p.ch <- outcome:
	default:
	}
	return nil
}

// DenyAgent denies everything an agent is waiting on (used by the kill switch).
func (b *Broker) DenyAgent(agent string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, p := range b.pending {
		if p.AgentID == agent {
			select {
			case p.ch <- Denied:
			default:
			}
		}
	}
}

// List returns the calls currently waiting for approval, oldest first.
func (b *Broker) List() []Pending {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]Pending, 0, len(b.pending))
	for _, p := range b.pending {
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out
}

func (b *Broker) changed() {
	if b.OnChange != nil {
		b.OnChange()
	}
}
