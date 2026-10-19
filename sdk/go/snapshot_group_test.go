package microsandbox

import (
	"context"
	"testing"
)

// Invalid option multiplicity must fail before loading a native library or publishing a group.
func TestSnapshotLoadRejectsMultipleOptions(t *testing.T) {
	_, err := Snapshot.Load(context.Background(), "history", nil, SnapshotImportOptions{}, SnapshotImportOptions{})
	if err == nil || err.Error() != "snapshot load accepts at most one options value" {
		t.Fatalf("expected option validation, got %v", err)
	}
}
