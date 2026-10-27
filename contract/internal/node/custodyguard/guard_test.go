package custodyguard

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func privateDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestWholeMutationAdmissionAndNestedContext(t *testing.T) {
	dir := privateDir(t)
	err := With(context.Background(), dir, func(ctx context.Context) error {
		if err := With(ctx, dir, func(context.Context) error { return nil }); err != nil {
			return err
		}
		deadline, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
		defer cancel()
		if err := With(deadline, dir, func(context.Context) error { t.Fatal("overlapping writer admitted"); return nil }); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("contender: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := With(context.Background(), dir, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestPendingFreezeRefusesOrdinaryWriter(t *testing.T) {
	dir := privateDir(t)
	if err := os.WriteFile(filepath.Join(dir, ProfileJournal), []byte("invalid or interrupted journal"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := With(context.Background(), dir, func(context.Context) error { t.Fatal("pending writer admitted"); return nil }); !errors.Is(err, ErrPending) {
		t.Fatal(err)
	}
	l, err := BeginUpgrade(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := l.Context(context.Background())
	if err := With(ctx, dir, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if err := With(ctx, dir, func(context.Context) error { t.Fatal("closed lease reused"); return nil }); !errors.Is(err, ErrPending) {
		t.Fatal(err)
	}
}

func TestLeaseCloseWaitsForNestedMutationWithoutBlockingReentry(t *testing.T) {
	dir := privateDir(t)
	l, err := BeginUpgrade(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	entered, finish, closed := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	result := make(chan error, 1)
	go func() {
		result <- With(l.Context(context.Background()), dir, func(ctx context.Context) error {
			close(entered)
			<-finish
			return With(ctx, dir, func(context.Context) error { return nil })
		})
	}()
	<-entered
	go func() { closed <- l.Close() }()
	select {
	case <-closed:
		t.Fatal("lease closed during mutation")
	case <-time.After(10 * time.Millisecond):
	}
	close(finish)
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("nested mutation deadlocked with Close")
	}
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("lease did not close")
	}
}

func TestCanceledUpgradeAdmissionRetainsExistingLease(t *testing.T) {
	dir := privateDir(t)
	l, err := BeginUpgrade(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := BeginUpgrade(ctx, dir); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if err := With(l.Context(context.Background()), dir, func(context.Context) error { return nil }); err != nil {
		t.Fatal("owner admission lost", err)
	}
}
