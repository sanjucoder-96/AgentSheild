package gateway

import (
	"testing"

	"pnc3-gateway/internal/approval"
)

// Each approval writes two audit events (held, then the outcome). The
// PostgreSQL audit table requires unique ids, so the two must differ.
func TestApprovalAuditRecordsHaveUniqueIDs(t *testing.T) {
	p := &approval.Pending{ID: "apr-123", DecisionID: "dec-1", Tool: "delete_all_emails"}
	held := approvalAuditRecord(p, "pending")
	done := approvalAuditRecord(p, approval.Denied)
	if held.ID == done.ID {
		t.Fatalf("held and outcome events share id %q", held.ID)
	}
	if held.Type != "approval" || done.Verdict != approval.Denied {
		t.Fatalf("unexpected records: %+v %+v", held, done)
	}
}
