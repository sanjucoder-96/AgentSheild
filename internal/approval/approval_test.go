package approval

import (
	"context"
	"testing"
	"time"
)

func TestWaitBlocksUntilHumanApproves(t *testing.T) {
	broker := NewBroker()
	pending := &Pending{ID: "apr-test-approve", AgentID: "support-agent", Tool: "delete_all_emails"}
	result := make(chan string, 1)

	go func() {
		result <- broker.Wait(context.Background(), pending, time.Second)
	}()

	deadline := time.Now().Add(time.Second)
	for len(broker.List()) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(broker.List()) != 1 {
		t.Fatal("approval was not registered as pending")
	}

	select {
	case got := <-result:
		t.Fatalf("approval completed before human resolution: %q", got)
	case <-time.After(20 * time.Millisecond):
	}

	if err := broker.Resolve(pending.ID, Approved); err != nil {
		t.Fatalf("resolve approval: %v", err)
	}

	select {
	case got := <-result:
		if got != Approved {
			t.Fatalf("approval result = %q, want %q", got, Approved)
		}
	case <-time.After(time.Second):
		t.Fatal("approval did not finish after human approval")
	}

	if got := broker.List(); len(got) != 0 {
		t.Fatalf("pending approvals after resolution = %d, want 0", len(got))
	}
}

func TestWaitReturnsHumanDenial(t *testing.T) {
	broker := NewBroker()
	pending := &Pending{ID: "apr-test-deny", AgentID: "support-agent", Tool: "delete_all_emails"}
	result := make(chan string, 1)

	go func() {
		result <- broker.Wait(context.Background(), pending, time.Second)
	}()

	deadline := time.Now().Add(time.Second)
	for len(broker.List()) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if err := broker.Resolve(pending.ID, Denied); err != nil {
		t.Fatalf("resolve denial: %v", err)
	}

	select {
	case got := <-result:
		if got != Denied {
			t.Fatalf("approval result = %q, want %q", got, Denied)
		}
	case <-time.After(time.Second):
		t.Fatal("approval did not finish after human denial")
	}
}
