//go:build linux || darwin

package store

import (
	"context"
	"fmt"
	"github.com/Telara-Labs/hilo/contract/record"
	"testing"
)

func TestRepositoryRetirementKeepsFenceAndPartialControlProgress(t *testing.T) {
	ctx := context.Background()
	f, b, _ := enrolledProducer(t)
	// These synthetic retained association ids model metadata variants already
	// verified and inventoried before leaving this node. No unsigned data is
	// admitted and no synthetic id is used as fresh repository authority.
	if err := f.w.s.write(ctx, func() error {
		for i := 0; i < repositoryRetirementBatch+1; i++ {
			if _, err := f.w.s.conn.ExecContext(ctx, "INSERT INTO repository_record VALUES(?,?,?)", record.H("retained-variant-fixture", fmt.Sprint(i)), b.ID, b.Generation); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	interrupted := &repositoryInterruptedSigner{worldSigner: worldSigner{f.w.key}, remaining: 1}
	controls, err := f.w.s.RevokeRepository(ctx, b.ID, interrupted)
	if Code(err) != "signing_unavailable" || len(controls) != 1 {
		t.Fatal("partial signing outcome", controls, err)
	}
	current, err := f.w.s.RepositoryBinding(ctx, b.ID)
	if err != nil || current.State != "retiring" || current.Generation != b.Generation+1 {
		t.Fatal("retirement fence rolled back", current, err)
	}
	var committed, pending int
	if err = f.w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM repository_retirement WHERE binding=? AND control!=''", b.ID).Scan(&committed); err != nil {
		t.Fatal(err)
	}
	if err = f.w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM repository_retirement WHERE binding=? AND control=''", b.ID).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if committed != repositoryRetirementBatch || pending == 0 {
		t.Fatal("partial durable retirement lost", committed, pending)
	}
	q := f.q
	q.ExpectedVersion = 2
	called := false
	if _, err = f.w.s.Capture(ctx, q, func(*CaptureTxn) (CommitPlan, error) { called = true; return f.plan, nil }); err == nil || called {
		t.Fatal("pending retirement admitted producer")
	}
	more, err := f.w.s.RevokeRepository(ctx, b.ID, worldSigner{f.w.key})
	if err != nil || len(more) != 1 {
		t.Fatal("resume signed retirement", more, err)
	}
	if more[0] == controls[0] {
		t.Fatal("retry replaced first durable control")
	}
	current, err = f.w.s.RepositoryBinding(ctx, b.ID)
	if err != nil || current.State != "retired" || current.Generation != b.Generation+1 {
		t.Fatal("retry changed generation or stayed pending", current, err)
	}
	if original := find(f.w.snapshot(), b.Observation); original.State != "live" || len(original.BodyJCS) == 0 {
		t.Fatal("original unbound observation lost")
	}
}
