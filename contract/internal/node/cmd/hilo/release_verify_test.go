package main

import (
	"context"
	"io"
	"strings"
	"testing"
)

func TestReleaseDirectoryRefusesUnauthenticatedInstallation(t *testing.T) {
	for _, op := range []string{"install", "upgrade"} {
		t.Run(op, func(t *testing.T) {
			err := runService(context.Background(), []string{op, "--release-dir", t.TempDir()}, io.Discard, strings.NewReader(""))
			if err == nil || err.Error() != "release_verification_failed" {
				t.Fatalf("untrusted release was not refused before installation: %v", err)
			}
			err = runService(context.Background(), []string{op, "--release-dir", t.TempDir(), "--sha256", strings.Repeat("0", 64)}, io.Discard, strings.NewReader(""))
			if err == nil || err.Error() != "invalid_arguments" {
				t.Fatalf("manifest override was not refused: %v", err)
			}
		})
	}
}
