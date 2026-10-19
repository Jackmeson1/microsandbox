package ffi

import (
	"context"
	"errors"
	"testing"
)

func TestRestoreGuestClockCancellationDoesNotRequireNativeLibrary(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := CheckRestoreGuestClock(ctx, "off"); !errors.Is(err, context.Canceled) {
		t.Fatalf("lost cancellation: %v", err)
	}
	if err := CheckRestoreGuestClock(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
}

func TestRestoreBootOptionsPreserveOmissionAndCancellation(t *testing.T) {
	if err := CheckRestoreBootOptions(context.Background(), RestoreOptions{}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	hostname := "child"
	for _, options := range []RestoreOptions{{Init: &InitOptions{Cmd: "auto"}}, {Hostname: &hostname}} {
		if err := CheckRestoreBootOptions(ctx, options); !errors.Is(err, context.Canceled) {
			t.Fatalf("lost cancellation: %v", err)
		}
	}
}
