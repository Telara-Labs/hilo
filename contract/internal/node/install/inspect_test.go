package install

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestInspectVerifiesReceiptWithoutMutation(t *testing.T) {
	ctx := context.Background()
	r, _ := receiptFixture(t)
	receipt, err := os.ReadFile(filepath.Join(r.Dir, "install.json"))
	if err != nil {
		t.Fatal(err)
	}
	got := Inspect(ctx, r.Dir)
	if got.State != "verified" || !got.Verified || got.SHA256 != r.SHA256 || got.Version != r.Version || got.DataDir != r.DataDir || got.Manager == "" {
		t.Fatalf("%+v", got)
	}
	if after, err := os.ReadFile(filepath.Join(r.Dir, "install.json")); err != nil || string(after) != string(receipt) {
		t.Fatal("inspect rewrote the receipt", err)
	}
	if err = writeIntent(r.Dir, r, "stop", ""); err != nil {
		t.Fatal(err)
	}
	if got = Inspect(ctx, r.Dir); got.State != "stopped" || !got.Verified {
		t.Fatalf("stopped %+v", got)
	}
	// A substituted image fails digest verification.
	if err = writeAtomic(r.Executable, []byte("substituted image\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if got = Inspect(ctx, r.Dir); got.State != "unverified" || got.Verified || got.Error != ErrUnverified.Error() {
		t.Fatalf("substituted %+v", got)
	}
	if got = Inspect(ctx, testRoot(t)); got.State != "absent" {
		t.Fatalf("absent %+v", got)
	}
	if got = Inspect(ctx, "relative/dir"); got.State != "unsafe" {
		t.Fatalf("relative %+v", got)
	}
}
