package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"pnc3-gateway/internal/approval"
)

func TestBenchmarkBinaryPath(t *testing.T) {
	dir := t.TempDir()
	gatewayPath := filepath.Join(dir, "gateway")
	if runtime.GOOS == "windows" {
		benchPath := filepath.Join(dir, "bench.exe")
		if err := os.WriteFile(benchPath, []byte("x"), 0o755); err != nil {
			t.Fatalf("write test bench binary: %v", err)
		}
		if got := benchmarkBinaryPath(gatewayPath); got != benchPath {
			t.Fatalf("benchmarkBinaryPath() = %q, want %q", got, benchPath)
		}
		return
	}
	benchPath := filepath.Join(dir, "bench")
	if err := os.WriteFile(benchPath, []byte("x"), 0o755); err != nil {
		t.Fatalf("write test bench binary: %v", err)
	}
	if got := benchmarkBinaryPath(gatewayPath); got != benchPath {
		t.Fatalf("benchmarkBinaryPath() = %q, want %q", got, benchPath)
	}
}

func TestApprovalAuditRecord(t *testing.T) {
	p := &approval.Pending{ID: "apr-123", DecisionID: "dec-456", AgentID: "support-agent", SessionID: "sess-1", Tool: "delete_all_emails", RuleIDs: []string{"tool-approval-requirement"}, Reason: "tool requires approval", Findings: []string{"needs review"}, Created: time.Now()}
	rec := approvalAuditRecord(p, "pending")
	if rec.Type != "approval" {
		t.Fatalf("approval record type = %q, want %q", rec.Type, "approval")
	}
	if rec.Verdict != "pending" {
		t.Fatalf("approval verdict = %q, want %q", rec.Verdict, "pending")
	}
	var detail map[string]string
	if err := json.Unmarshal(rec.Detail, &detail); err != nil {
		t.Fatalf("unmarshal detail: %v", err)
	}
	if detail["approval"] != "pending" {
		t.Fatalf("detail[%q] = %q, want %q", "approval", detail["approval"], "pending")
	}
}
