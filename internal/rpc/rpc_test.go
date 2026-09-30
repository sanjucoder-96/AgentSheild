package rpc

import "testing"

func TestStrictRejectsDuplicateKeys(t *testing.T) {
	bad := [][]byte{
		[]byte(`{"jsonrpc":"2.0","method":"tools/call","method":"ping"}`),
		[]byte(`{"jsonrpc":"2.0","method":"x","NAME":"a","name":"b"}`), // case-variant duplicate
	}
	for _, b := range bad {
		if _, err := ParseStrict(b, 32); err == nil {
			t.Errorf("expected duplicate-key rejection for %s", b)
		}
	}
}

func TestStrictRejectsBatchAndDepth(t *testing.T) {
	if _, err := ParseStrict([]byte(`[{"jsonrpc":"2.0","method":"x"}]`), 32); Code(err) != "batch_not_supported" {
		t.Errorf("batch should be rejected, got %v", err)
	}
	deep := []byte(`{"jsonrpc":"2.0","method":"x","params":{"a":{"b":{"c":{"d":1}}}}}`)
	if _, err := ParseStrict(deep, 3); err == nil {
		t.Errorf("expected depth rejection")
	}
}

func TestStrictAcceptsValid(t *testing.T) {
	good := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send_email","arguments":{"to":"a@b.example"}}}`)
	req, err := ParseStrict(good, 32)
	if err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	p, err := ParseToolCall(req.Params, true)
	if err != nil || p.Name != "send_email" {
		t.Fatalf("tool call parse failed: %v", err)
	}
}

func TestStrictRejectsUnknownField(t *testing.T) {
	if _, err := ParseStrict([]byte(`{"jsonrpc":"2.0","method":"x","bogus":1}`), 32); err == nil {
		t.Errorf("expected unknown-field rejection")
	}
}
