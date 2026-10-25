package syncnode

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	"github.com/Telara-Labs/telara-memory/contract/record"
)

// A restored hosted-enrolled node holds restored data until one round has
// pulled and enforced every control to the HELLO head. A blocked control
// leaves the hold in place; only a complete enforcement pass releases it.
func TestRestoreFenceReleasedOnlyByCompleteControlEnforcement(t *testing.T) {
	for _, blocked := range []bool{true, false} {
		w := newWorld(t)
		ctx := context.Background()
		task := w.task(1, repoA, "active")
		w.enroll()
		sel, err := w.st.SelectBundle(ctx, []string{task.ID})
		if err != nil || len(sel.Data) != 1 {
			t.Fatal(sel, err)
		}
		report, err := w.st.ImportBundle(ctx, store.BundleImport{LocalKeyID: w.genesis, Keyring: sel.Keyring, Data: sel.Data})
		if err != nil || !report.Fenced {
			t.Fatal("hosted restore not fenced", report, err)
		}
		if blocked {
			bad := w.control(2, record.KindRetraction, strings.Repeat("f", 64))
			bad.V = record.Version + 1
			w.hosted.addControl(bad)
		}
		wk := w.worker()
		w.selectRepo(wk, repoA)
		err = wk.Round(ctx)
		if blocked != errors.Is(err, ErrControlBlocked) || !blocked && err != nil {
			t.Fatalf("blocked=%v round %v", blocked, err)
		}
		pending, err := w.st.RestorePending(ctx)
		if err != nil || pending != blocked {
			t.Fatalf("blocked=%v restore still pending=%v %v", blocked, pending, err)
		}
	}
}
