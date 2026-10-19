//go:build snapshot_live && microsandbox_ffi_path

package microsandbox

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// This scenario needs a fresh MSB_HOME and a native archive for the current host.
// Guest contents, rather than successful launch alone, establish exact selection.
func TestSnapshotGroupsLive(t *testing.T) {
	archive := os.Getenv("MSB_TEST_GROUP_ARCHIVE")
	if archive == "" {
		t.Skip("requires native archive and isolated MSB_HOME")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if _, err := Checkpoint.LoadMany(ctx, []string{archive}, SnapshotLoadOptions{Group: "seed"}); err != nil {
		t.Fatal(err)
	}
	seed, err := Snapshot.Get(ctx, "seed")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := seed.Checkpoint(ctx); err == nil || !strings.Contains(err.Error(), "unbound") {
		t.Fatalf("unbound capture: %v", err)
	}
	source, err := seed.SpawnSandbox(ctx, "go-source", WithRestoreCPUs(2), WithRestoreMemory(512))
	if err != nil {
		t.Fatal(err)
	}
	cleanup := func(sandbox *Sandbox) {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = sandbox.Stop(cleanupCtx)
		_ = RemoveSandbox(cleanupCtx, sandbox.Name())
		_ = sandbox.Close()
	}
	defer cleanup(source)
	write := func(value string) {
		t.Helper()
		output, err := source.Exec(ctx, "sh", []string{"-c", "echo " + value + " > /go-state; sync"})
		if err != nil || !output.Success() {
			t.Fatalf("write guest: %v %+v", err, output)
		}
	}
	sourceHandle, err := GetSandbox(ctx, source.Name())
	if err != nil {
		t.Fatal(err)
	}
	refreshed, err := sourceHandle.Refresh(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := refreshed.Snapshot(ctx, "handle-history"); err != nil {
		t.Fatal(err)
	}
	sources, err := ListSandboxes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, handle := range sources.Sandboxes {
		if handle.ID() == source.ID() {
			found = true
			if _, err := handle.Snapshot(ctx, "listed-history"); err != nil {
				t.Fatal(err)
			}
		}
	}
	if !found {
		t.Fatal("source missing from listing")
	}

	legacy, err := ffi.SandboxHandleSnapshot(ctx, source.Name(), "legacy-member")
	if err != nil {
		t.Fatal(err)
	}
	if legacy.HeadUpdate == nil || legacy.HeadUpdate.Group != source.Name() {
		t.Fatalf("released native capture symbol changed its group/member interpretation: %+v", legacy)
	}

	write("go-A")
	first, err := source.Snapshot(ctx, "history", WithSnapshotCaptureConfig(SnapshotCaptureConfig{Name: "base", RecordIntegrity: true}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.Snapshot(ctx, "history"); err == nil {
		t.Fatal("duplicate creation appended")
	}
	write("go-B")
	second, err := first.Snapshot.Checkpoint(ctx, WithSnapshotCaptureConfig(SnapshotCaptureConfig{Name: "next", RecordIntegrity: true}))
	if err != nil {
		t.Fatal(err)
	}
	if first.HeadUpdate.Head == nil || *first.HeadUpdate.Head != first.Checkpoint.ID() {
		t.Fatal("initial result lost its own head outcome")
	}
	if _, err := first.Snapshot.ClearHead(ctx); err != nil {
		t.Fatal(err)
	}
	if head, err := first.Snapshot.Head(ctx); err != nil || head != nil {
		t.Fatalf("headless state: %v %v", head, err)
	}
	if _, err := first.Snapshot.SpawnSandbox(ctx, ""); err == nil {
		t.Fatal("headless spawn succeeded")
	}
	if _, err := first.Snapshot.SetHead(ctx, "base"); err != nil {
		t.Fatal(err)
	}
	if err := first.Checkpoint.Save(ctx, filepath.Join(os.Getenv("MSB_HOME"), "export.msb"), SnapshotSaveOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Checkpoint.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	if err := source.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if err := RemoveSandbox(ctx, source.Name()); err != nil {
		t.Fatal(err)
	}
	for index, checkpoint := range []*SnapshotArtifact{first.Checkpoint, second.Checkpoint} {
		_, results := checkpoint.SpawnSandboxWithProgress(ctx, "", WithRestoreCPUs(2), WithRestoreMemory(512))
		result := <-results // Deliberately ignore progress: telemetry must never block completion.
		if result.Err != nil {
			t.Fatal(result.Err)
		}
		child := result.Sandbox
		func() {
			defer cleanup(child)
			if child.Name() == "" {
				t.Error("generated name not returned")
			}
			output, err := child.Exec(ctx, "cat", []string{"/go-state"})
			expected := []string{"go-A", "go-B"}[index]
			if err != nil || strings.TrimSpace(output.Stdout()) != expected {
				t.Fatalf("guest contents: %v %+v", err, output)
			}
			t.Logf("verified %s from %s after source deletion", expected, checkpoint.ID())
		}()
	}
	if _, err := first.Snapshot.Checkpoint(ctx); err == nil {
		t.Fatal("orphaned capture succeeded")
	}
	replacement, err := seed.SpawnSandbox(ctx, source.Name(), WithRestoreCPUs(2), WithRestoreMemory(512))
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup(replacement)
	if _, err := sourceHandle.Snapshot(ctx, "stale-history"); !IsKind(err, ErrSandboxReplaced) {
		t.Fatalf("stale source capture: expected replacement refusal, got %v", err)
	}
	if _, err := Snapshot.Get(ctx, "stale-history"); err == nil {
		t.Fatal("stale capture created a group")
	}

}
