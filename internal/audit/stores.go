package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ---------- JSONL file (default, zero setup) ----------

// FileStore keeps the audit log as signed JSON lines in state/audit.jsonl (the zero-setup default).
type FileStore struct {
	signer *Signer
	path   string
	mu     sync.Mutex
	recent []Record
	last   string
	seq    int64
}

// NewFileStore opens or creates the JSONL audit log and resumes its hash chain.
func NewFileStore(stateDir string, s *Signer) (*FileStore, error) {
	fs := &FileStore{signer: s, path: filepath.Join(stateDir, "audit.jsonl")}
	recs, err := fs.readAll()
	if err != nil {
		return nil, err
	}
	if n := len(recs); n > 0 {
		fs.last, fs.seq = recs[n-1].Hash, recs[n-1].Seq
		if n > 2000 {
			recs = recs[n-2000:]
		}
		fs.recent = recs
	}
	return fs, nil
}

// Backend names this store for the dashboard.
func (fs *FileStore) Backend() string { return "file:" + fs.path }

func (fs *FileStore) readAll() ([]Record, error) {
	f, err := os.Open(fs.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Record
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 8<<20)
	for sc.Scan() {
		var r Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return nil, fmt.Errorf("audit log line %d: %w", len(out)+1, err)
		}
		out = append(out, r)
	}
	return out, sc.Err()
}

// Append links the record into the hash chain, signs it and writes it to disk.
func (fs *FileStore) Append(r *Record) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	line, err := fs.signer.seal(r, fs.seq+1, fs.last)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(fs.path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(fs.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return err
	}
	fs.seq, fs.last = r.Seq, r.Hash
	fs.recent = append(fs.recent, *r)
	if len(fs.recent) > 2000 {
		fs.recent = fs.recent[len(fs.recent)-2000:]
	}
	return nil
}

// Recent returns up to limit of the newest records that match filter.
func (fs *FileStore) Recent(limit int, filter func(*Record) bool) ([]Record, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	var out []Record
	for i := len(fs.recent) - 1; i >= 0 && len(out) < limit; i-- {
		if filter == nil || filter(&fs.recent[i]) {
			out = append(out, fs.recent[i])
		}
	}
	return out, nil
}

// Verify re-reads the file from disk, so edits made outside the gateway are caught.
func (fs *FileStore) Verify() (VerifyResult, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	recs, err := fs.readAll()
	if err != nil {
		return VerifyResult{OK: false, Problem: err.Error(), PublicKey: fs.signer.PublicHex()}, nil
	}
	return verifyAll(fs.signer.Pub, recs), nil
}

// ---------- PostgreSQL ----------

// PGStore keeps the audit log in PostgreSQL, for example Amazon RDS.
type PGStore struct {
	signer *Signer
	pool   *pgxpool.Pool
}

// NewPGStore connects to PostgreSQL and creates the audit table if needed.
func NewPGStore(ctx context.Context, url string, s *Signer) (*PGStore, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, err
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(cctx); err != nil {
		return nil, err
	}
	if _, err := pool.Exec(ctx, Schema); err != nil {
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return &PGStore{signer: s, pool: pool}, nil
}

// Backend names this store for the dashboard.
func (p *PGStore) Backend() string { return "postgres" }

// Schema matches migrations/001_init.sql (the audit table is created here too
// so the gateway works against an empty database).
const Schema = `
CREATE TABLE IF NOT EXISTS audit_log (
  seq          BIGINT PRIMARY KEY,
  id           TEXT UNIQUE NOT NULL,
  ts           TIMESTAMPTZ NOT NULL,
  type         TEXT NOT NULL,
  agent_id     TEXT,
  tool         TEXT,
  verdict      TEXT,
  record_json  TEXT NOT NULL,
  record       JSONB NOT NULL,
  prev_hash    TEXT NOT NULL,
  hash         TEXT NOT NULL,
  sig          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_log_agent_idx ON audit_log (agent_id, seq DESC);
CREATE INDEX IF NOT EXISTS audit_log_verdict_idx ON audit_log (verdict, seq DESC);`

// Append links and signs the record inside a transaction; an advisory lock keeps the chain consistent across gateway replicas.
func (p *PGStore) Append(r *Record) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	// One writer at a time, across all gateway replicas.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(424242)`); err != nil {
		return err
	}
	var seq int64
	var prev string
	err = tx.QueryRow(ctx, `SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1`).Scan(&seq, &prev)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	line, err := p.signer.seal(r, seq+1, prev)
	if err != nil {
		return err
	}
	ts, _ := time.Parse(time.RFC3339Nano, r.Time)
	_, err = tx.Exec(ctx, `INSERT INTO audit_log (seq,id,ts,type,agent_id,tool,verdict,record_json,record,prev_hash,hash,sig)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11,$12)`,
		r.Seq, r.ID, ts, r.Type, r.AgentID, r.Tool, r.Verdict, string(line), string(line), r.PrevHash, r.Hash, r.Sig)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Recent returns up to limit of the newest records that match filter.
func (p *PGStore) Recent(limit int, filter func(*Record) bool) ([]Record, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rows, err := p.pool.Query(ctx, `SELECT record_json FROM audit_log ORDER BY seq DESC LIMIT $1`, limit*4)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Record
	for rows.Next() && len(out) < limit {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		var r Record
		if err := json.Unmarshal([]byte(s), &r); err == nil && (filter == nil || filter(&r)) {
			out = append(out, r)
		}
	}
	return out, rows.Err()
}

// Verify re-reads every record in order and checks the hash chain and every signature.
func (p *PGStore) Verify() (VerifyResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rows, err := p.pool.Query(ctx, `SELECT record_json FROM audit_log ORDER BY seq ASC`)
	if err != nil {
		return VerifyResult{}, err
	}
	defer rows.Close()
	var recs []Record
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return VerifyResult{}, err
		}
		var r Record
		if err := json.Unmarshal([]byte(s), &r); err != nil {
			return VerifyResult{OK: false, Problem: "unparseable record", PublicKey: p.signer.PublicHex()}, nil
		}
		recs = append(recs, r)
	}
	return verifyAll(p.signer.Pub, recs), rows.Err()
}
