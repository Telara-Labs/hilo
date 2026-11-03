//go:build windows

package vault

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"

	"github.com/Telara-Labs/hilo/contract/internal/node/ipc"
)

func windowsProfile(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	p, err := ipc.Resolve(filepath.Join(root, "data"), filepath.Join(root, "run"))
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Prepare(); err != nil {
		t.Fatal(err)
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal(err)
	}
	return p.Data, hex.EncodeToString(id[:])
}

func TestWindowsProfileCreationReceiptAndPlannedRecovery(t *testing.T) {
	dir, handle := windowsProfile(t)
	ctx := context.Background()
	value := []byte("synthetic pending profile credential")
	defer New().Delete(ctx, handle)
	v := ForProfile(dir)
	if err := v.Put(ctx, handle, value); err != nil {
		t.Fatal(err)
	}
	r, err := readWindowsCreator(dir, handle)
	if err != nil || r.Phase != "bound" {
		t.Fatal(r.Phase, err)
	}
	planned := r
	planned.Phase = "planned"
	if err := writeWindowsCreator(dir, &r, planned); err != nil {
		t.Fatal(err)
	}
	b, err := ForProfile(dir).Get(ctx, handle)
	if err != nil || !bytes.Equal(b, value) {
		t.Fatal(err)
	}
	clear(b)
	read, err := readWindowsCreator(dir, handle)
	if err != nil || read != planned {
		t.Fatal("Get changed planned evidence", err)
	}
	if err := ForProfile(dir).AbandonPlanned(ctx, handle); err != nil {
		t.Fatal(err)
	}
	if _, err := New().Get(ctx, handle); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if err := ForProfile(dir).AbandonPlanned(ctx, handle); err != nil {
		t.Fatal("retry", err)
	}
}

func TestWindowsPendingAbandonRetainsUnrecordedAndCollidingItems(t *testing.T) {
	dir, handle := windowsProfile(t)
	ctx := context.Background()
	want := []byte("foreign same-name credential")
	if err := New().Put(ctx, handle, want); err != nil {
		t.Fatal(err)
	}
	defer New().Delete(ctx, handle)
	if err := ForProfile(dir).AbandonPlanned(ctx, handle); err != nil {
		t.Fatal(err)
	}
	if err := ForProfile(dir).Put(ctx, handle, []byte("replacement")); !errors.Is(err, ErrExists) {
		t.Fatal(err)
	}
	if err := ForProfile(dir).AbandonPlanned(ctx, handle); !errors.Is(err, ErrUnavailable) {
		t.Fatal("collision adopted", err)
	}
	if err := ForProfile(dir).Delete(ctx, handle); !errors.Is(err, ErrUnavailable) {
		t.Fatal("collision deleted", err)
	}
	b, err := New().Get(ctx, handle)
	if err != nil || !bytes.Equal(b, want) {
		t.Fatal("foreign item changed", err)
	}
	clear(b)
}
