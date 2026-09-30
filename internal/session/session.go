// Package session tracks per-session data-flow labels and agent revocation.
//
// Labels: a session becomes "tainted" once it has read untrusted content, and
// "has private data" once it has read private records. Values seen in those
// reads are fingerprinted so later calls can be checked for where their
// arguments came from and what they carry.
package session

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

const ttl = 2 * time.Hour

type State struct {
	Tainted         bool
	HasPrivate      bool
	UntrustedValues map[string]struct{}
	PrivateValues   map[string]struct{}
}

type Store interface {
	Get(ctx context.Context, id string) (State, error)
	AddUntrusted(ctx context.Context, id string, values []string) error
	AddPrivate(ctx context.Context, id string, values []string) error
	Revoke(ctx context.Context, agent string) error
	Restore(ctx context.Context, agent string) error
	IsRevoked(ctx context.Context, agent string) (bool, error)
	Revoked(ctx context.Context) ([]string, error)
	Backend() string
}

// ---------- memory ----------

type memSession struct {
	State
	touched time.Time
}

type Memory struct {
	mu       sync.Mutex
	sessions map[string]*memSession
	revoked  map[string]bool
}

func NewMemory() *Memory {
	return &Memory{sessions: map[string]*memSession{}, revoked: map[string]bool{}}
}

func (m *Memory) Backend() string { return "memory" }

func (m *Memory) get(id string) *memSession {
	s := m.sessions[id]
	if s == nil || time.Since(s.touched) > ttl {
		s = &memSession{State: State{UntrustedValues: map[string]struct{}{}, PrivateValues: map[string]struct{}{}}}
		m.sessions[id] = s
	}
	s.touched = time.Now()
	return s
}

func (m *Memory) Get(_ context.Context, id string) (State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.get(id)
	c := State{Tainted: s.Tainted, HasPrivate: s.HasPrivate,
		UntrustedValues: map[string]struct{}{}, PrivateValues: map[string]struct{}{}}
	for k := range s.UntrustedValues {
		c.UntrustedValues[k] = struct{}{}
	}
	for k := range s.PrivateValues {
		c.PrivateValues[k] = struct{}{}
	}
	return c, nil
}

func (m *Memory) AddUntrusted(_ context.Context, id string, values []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.get(id)
	s.Tainted = true
	for _, v := range values {
		s.UntrustedValues[strings.ToLower(v)] = struct{}{}
	}
	return nil
}

func (m *Memory) AddPrivate(_ context.Context, id string, values []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.get(id)
	s.HasPrivate = true
	for _, v := range values {
		s.PrivateValues[strings.ToLower(v)] = struct{}{}
	}
	return nil
}

func (m *Memory) Revoke(_ context.Context, a string) error {
	m.mu.Lock()
	m.revoked[a] = true
	m.mu.Unlock()
	return nil
}

func (m *Memory) Restore(_ context.Context, a string) error {
	m.mu.Lock()
	delete(m.revoked, a)
	m.mu.Unlock()
	return nil
}

func (m *Memory) IsRevoked(_ context.Context, a string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.revoked[a], nil
}

func (m *Memory) Revoked(_ context.Context) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for a := range m.revoked {
		out = append(out, a)
	}
	sort.Strings(out)
	return out, nil
}

// ---------- redis ----------

type Redis struct{ c *redis.Client }

func NewRedis(url string) (*Redis, error) {
	opt, err := redis.ParseURL(url)
	if err != nil {
		return nil, err
	}
	c := redis.NewClient(opt)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := c.Ping(ctx).Err(); err != nil {
		return nil, err
	}
	return &Redis{c: c}, nil
}

func (r *Redis) Backend() string { return "redis" }

const revokedKey = "gw:revoked"

func key(id, part string) string { return "gw:sess:" + id + ":" + part }

func (r *Redis) Get(ctx context.Context, id string) (State, error) {
	st := State{UntrustedValues: map[string]struct{}{}, PrivateValues: map[string]struct{}{}}
	pipe := r.c.Pipeline()
	flags := pipe.HGetAll(ctx, key(id, "flags"))
	unt := pipe.SMembers(ctx, key(id, "untrusted"))
	prv := pipe.SMembers(ctx, key(id, "private"))
	if _, err := pipe.Exec(ctx); err != nil && err != redis.Nil {
		return st, err
	}
	f := flags.Val()
	st.Tainted, st.HasPrivate = f["tainted"] == "1", f["private"] == "1"
	for _, v := range unt.Val() {
		st.UntrustedValues[v] = struct{}{}
	}
	for _, v := range prv.Val() {
		st.PrivateValues[v] = struct{}{}
	}
	return st, nil
}

func (r *Redis) add(ctx context.Context, id, flag, set string, values []string) error {
	pipe := r.c.TxPipeline()
	pipe.HSet(ctx, key(id, "flags"), flag, "1")
	pipe.Expire(ctx, key(id, "flags"), ttl)
	if len(values) > 0 {
		members := make([]any, len(values))
		for i, v := range values {
			members[i] = strings.ToLower(v)
		}
		pipe.SAdd(ctx, key(id, set), members...)
		pipe.Expire(ctx, key(id, set), ttl)
	}
	_, err := pipe.Exec(ctx)
	return err
}

func (r *Redis) AddUntrusted(ctx context.Context, id string, v []string) error {
	return r.add(ctx, id, "tainted", "untrusted", v)
}

func (r *Redis) AddPrivate(ctx context.Context, id string, v []string) error {
	return r.add(ctx, id, "private", "private", v)
}

func (r *Redis) Revoke(ctx context.Context, a string) error  { return r.c.SAdd(ctx, revokedKey, a).Err() }
func (r *Redis) Restore(ctx context.Context, a string) error { return r.c.SRem(ctx, revokedKey, a).Err() }

func (r *Redis) IsRevoked(ctx context.Context, a string) (bool, error) {
	return r.c.SIsMember(ctx, revokedKey, a).Result()
}

func (r *Redis) Revoked(ctx context.Context) ([]string, error) {
	out, err := r.c.SMembers(ctx, revokedKey).Result()
	sort.Strings(out)
	return out, err
}
