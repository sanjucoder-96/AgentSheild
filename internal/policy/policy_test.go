package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveAndDeletePolicyFile(t *testing.T) {
	dir := t.TempDir()
	base := `@id("base-policy")
@reason("base")
permit (principal, action, resource);`
	if err := os.WriteFile(filepath.Join(dir, "00-base.cedar"), []byte(base), 0o644); err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(dir)
	if err != nil {
		t.Fatal(err)
	}
	created := `@id("created-policy")
@reason("created")
permit (principal, action, resource);`
	if err := engine.Save("90-created.cedar", created); err != nil {
		t.Fatalf("save policy: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "90-created.cedar")); err != nil {
		t.Fatalf("policy file was not created: %v", err)
	}
	if err := engine.Delete("90-created.cedar"); err != nil {
		t.Fatalf("delete policy: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "90-created.cedar")); !os.IsNotExist(err) {
		t.Fatalf("policy file still exists, stat error: %v", err)
	}
}
