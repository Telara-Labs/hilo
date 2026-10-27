//go:build linux

package vault

import (
	"bytes"
	"context"
	"testing"
)

func TestLinuxPendingContextAbandonUsesExistingCreationEvidence(t *testing.T) {
	secretModes(t, func(t *testing.T, mode string) {
		s, _ := privateSecretService(t, mode)
		data := linuxProfile(t)
		ctx := context.Background()
		first, pending := linuxTestHandle, randomHandle(t)
		if err := ForProfile(data).Put(ctx, first, []byte("installed profile credential")); err != nil {
			t.Fatal(err)
		}
		if err := ForProfile(data).AbandonPlanned(ctx, pending); err != nil {
			t.Fatal("unattempted", err)
		}
		s.mu.Lock()
		s.loseReply = true
		s.mu.Unlock()
		if err := ForProfile(data).Put(ctx, pending, []byte("pending context credential")); err != ErrUnavailable {
			t.Fatal(err)
		}
		s.mu.Lock()
		s.loseReply = false
		s.mu.Unlock()
		if err := ForProfile(data).AbandonPlanned(ctx, pending); err != nil {
			t.Fatal("interrupted native create", err)
		}
		if err := ForProfile(data).AbandonPlanned(ctx, pending); err != nil {
			t.Fatal("retry", err)
		}
		b, err := ForProfile(data).Get(ctx, first)
		if err != nil || !bytes.Equal(b, []byte("installed profile credential")) {
			t.Fatal("unrelated credential changed", err)
		}
		clear(b)
	})
}
