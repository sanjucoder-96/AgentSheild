// Command gatewayctl is the operator CLI.
//
//	gatewayctl token --agent support-agent            mint a dev agent token
//	gatewayctl audit verify                           verify the file audit log offline
//	gatewayctl audit tamper --seq 3                   edit one record (demo: verify must fail)
package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"pnc3-gateway/internal/audit"
	"pnc3-gateway/internal/auth"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "token":
		token(os.Args[2:])
	case "audit":
		if len(os.Args) < 3 {
			usage()
		}
		switch os.Args[2] {
		case "verify":
			verify(os.Args[3:])
		case "tamper":
			tamper(os.Args[3:])
		default:
			usage()
		}
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  gatewayctl token --agent <id> [--ttl 8h]
  gatewayctl audit verify [--state-dir state]
  gatewayctl audit tamper --seq <n> [--state-dir state]`)
	os.Exit(2)
}

func token(args []string) {
	fs := flag.NewFlagSet("token", flag.ExitOnError)
	agent := fs.String("agent", "support-agent", "agent id (must exist in gateway.yaml)")
	ttl := fs.Duration("ttl", 8*time.Hour, "token lifetime")
	_ = fs.Parse(args)
	secret := os.Getenv("GATEWAY_JWT_SECRET")
	if secret == "" {
		secret = "dev-jwt-secret-change-me"
	}
	t, err := auth.IssueDevToken(secret, *agent, "operator", *ttl)
	if err != nil {
		fail(err)
	}
	fmt.Println(t)
}

func verify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	dir := fs.String("state-dir", "state", "gateway state directory")
	_ = fs.Parse(args)
	pub := publicKey(*dir)
	lines := readLines(filepath.Join(*dir, "audit.jsonl"))
	prev := ""
	for i, line := range lines {
		var r audit.Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			fmt.Printf("FAIL line %d: unparseable\n", i+1)
			os.Exit(1)
		}
		if r.PrevHash != prev {
			fmt.Printf("FAIL record %d: chain broken (prev_hash mismatch)\n", r.Seq)
			os.Exit(1)
		}
		hash, sig := r.Hash, r.Sig
		r.Hash, r.Sig = "", ""
		body, _ := json.Marshal(r)
		sum := sha256.Sum256(body)
		if hex.EncodeToString(sum[:]) != hash {
			fmt.Printf("FAIL record %d: content modified (hash mismatch)\n", r.Seq)
			os.Exit(1)
		}
		sb, _ := hex.DecodeString(sig)
		if !ed25519.Verify(pub, sum[:], sb) {
			fmt.Printf("FAIL record %d: bad signature\n", r.Seq)
			os.Exit(1)
		}
		prev = hash
	}
	fmt.Printf("OK: %d records, chain and signatures valid\n", len(lines))
}

// tamper flips a decision in place without re-signing, as an attacker covering tracks would.
func tamper(args []string) {
	fs := flag.NewFlagSet("tamper", flag.ExitOnError)
	dir := fs.String("state-dir", "state", "gateway state directory")
	seq := fs.Int64("seq", 1, "record to modify")
	_ = fs.Parse(args)
	path := filepath.Join(*dir, "audit.jsonl")
	lines := readLines(path)
	done := false
	for i, line := range lines {
		var r audit.Record
		if json.Unmarshal([]byte(line), &r) == nil && r.Seq == *seq {
			switch {
			case strings.Contains(line, `"verdict":"deny"`):
				lines[i] = strings.Replace(line, `"verdict":"deny"`, `"verdict":"allow"`, 1)
			default:
				lines[i] = strings.Replace(line, `"type":"`, `"type":"x`, 1)
			}
			done = true
		}
	}
	if !done {
		fail(fmt.Errorf("no record with seq %d", *seq))
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		fail(err)
	}
	fmt.Printf("Record %d modified. Now run: gatewayctl audit verify\n", *seq)
}

func publicKey(dir string) ed25519.PublicKey {
	b, err := os.ReadFile(filepath.Join(dir, "audit_ed25519.key"))
	if err != nil {
		fail(err)
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		fail(err)
	}
	return ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
}

func readLines(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		fail(err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 8<<20)
	for sc.Scan() {
		if s := strings.TrimSpace(sc.Text()); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
