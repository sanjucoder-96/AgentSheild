// Package audit writes a tamper-evident log of every decision and admin event.
//
// Each record stores the hash of the previous record, its own SHA-256 hash and
// an Ed25519 signature over that hash. Editing, deleting or reordering any
// record breaks verification from that point on.
package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type Record struct {
	Seq            int64            `json:"seq"`
	ID             string           `json:"id"`
	Time           string           `json:"time"`
	Type           string           `json:"type"` // decision | approval | revocation | manifest | policy
	AgentID        string           `json:"agent_id,omitempty"`
	SessionID      string           `json:"session_id,omitempty"`
	Tool           string           `json:"tool,omitempty"`
	Verdict        string           `json:"verdict,omitempty"`
	RuleIDs        []string         `json:"rule_ids,omitempty"`
	Reason         string           `json:"reason,omitempty"`
	Profile        string           `json:"profile,omitempty"`
	ArgsHash       string           `json:"args_hash,omitempty"`
	Args           json.RawMessage  `json:"args,omitempty"`
	Facts          map[string]bool  `json:"facts,omitempty"`
	Findings       []string         `json:"findings,omitempty"`
	Destinations   json.RawMessage  `json:"destinations,omitempty"`
	StageMicros    map[string]int64 `json:"stage_us,omitempty"`
	OverheadMicros int64            `json:"overhead_us,omitempty"`
	Detail         json.RawMessage  `json:"detail,omitempty"`
	PrevHash       string           `json:"prev_hash"`
	Hash           string           `json:"hash"`
	Sig            string           `json:"sig"`
}

// VerifyResult is returned by Verify.
type VerifyResult struct {
	OK        bool   `json:"ok"`
	Records   int    `json:"records"`
	BrokenAt  int64  `json:"broken_at,omitempty"`
	Problem   string `json:"problem,omitempty"`
	PublicKey string `json:"public_key"`
}

type Store interface {
	Append(r *Record) error
	Recent(limit int, filter func(*Record) bool) ([]Record, error)
	Verify() (VerifyResult, error)
	Backend() string
}

type Signer struct {
	priv ed25519.PrivateKey
	Pub  ed25519.PublicKey
}

// LoadSigner reads or creates the audit signing key in the state directory.
func LoadSigner(stateDir string) (*Signer, error) {
	path := filepath.Join(stateDir, "audit_ed25519.key")
	if b, err := os.ReadFile(path); err == nil {
		seed, err := hex.DecodeString(string(b))
		if err != nil || len(seed) != ed25519.SeedSize {
			return nil, errors.New("corrupt audit key file")
		}
		priv := ed25519.NewKeyFromSeed(seed)
		return &Signer{priv: priv, Pub: priv.Public().(ed25519.PublicKey)}, nil
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(priv.Seed())), 0o600); err != nil {
		return nil, err
	}
	return &Signer{priv: priv, Pub: pub}, nil
}

func (s *Signer) PublicHex() string { return hex.EncodeToString(s.Pub) }

// seal fills PrevHash, Hash and Sig. The hash covers the record with Hash and Sig empty.
func (s *Signer) seal(r *Record, seq int64, prev string) ([]byte, error) {
	r.Seq, r.PrevHash, r.Hash, r.Sig = seq, prev, "", ""
	if r.Time == "" {
		r.Time = time.Now().UTC().Format(time.RFC3339Nano)
	}
	body, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	r.Hash = hex.EncodeToString(sum[:])
	r.Sig = hex.EncodeToString(ed25519.Sign(s.priv, sum[:]))
	return json.Marshal(r)
}

// check verifies one record against the expected previous hash.
func check(pub ed25519.PublicKey, r Record, prev string) error {
	if r.PrevHash != prev {
		return errors.New("chain broken: prev_hash does not match the previous record")
	}
	hash, sig := r.Hash, r.Sig
	r.Hash, r.Sig = "", ""
	body, _ := json.Marshal(r)
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != hash {
		return errors.New("record content was modified (hash mismatch)")
	}
	sb, err := hex.DecodeString(sig)
	if err != nil || !ed25519.Verify(pub, sum[:], sb) {
		return errors.New("invalid signature")
	}
	return nil
}

func verifyAll(pub ed25519.PublicKey, recs []Record) VerifyResult {
	res := VerifyResult{OK: true, Records: len(recs), PublicKey: hex.EncodeToString(pub)}
	prev := ""
	for _, r := range recs {
		if err := check(pub, r, prev); err != nil {
			res.OK, res.BrokenAt, res.Problem = false, r.Seq, fmt.Sprintf("record %d: %v", r.Seq, err)
			return res
		}
		prev = r.Hash
	}
	return res
}

func NewID(prefix string) string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return prefix + "-" + hex.EncodeToString(b)
}
