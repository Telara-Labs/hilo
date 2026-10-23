package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
	"strings"
	"testing"
)

func TestKernelAuthorityMissingBodyAndEpochMismatchRefuse(t *testing.T) {
	for _, mode := range []string{"missing_body", "epoch", "signature"} {
		t.Run(mode, func(t *testing.T) {
			k := newKernel(t)
			ctx := context.Background()
			var q string
			switch mode {
			case "missing_body":
				q = "DELETE FROM record_body WHERE id='" + k.genesis.AdvisoryID + "'"
			case "epoch":
				q = "UPDATE meta SET authority_epoch=authority_epoch+1"
			case "signature":
				q = "UPDATE record SET sigs='[]' WHERE id='" + k.genesis.AdvisoryID + "'"
			}
			if _, err := k.s.conn.ExecContext(ctx, q); err != nil {
				t.Fatal(err)
			}
			_, err := k.e.Authenticate(ctx, k.proof)
			if Code(err) != "authority_evaluation_required" && Code(err) != "corrupt_database" {
				t.Fatal("partial key history authorized", mode, err)
			}
		})
	}
}
func TestKernelProjectionHoldKeepsBoundedKeyAuthority(t *testing.T) {
	k := newKernel(t)
	ctx := context.Background()
	root := k.execute("root", "local.create_task", map[string]any{"goal": "root"})
	k.release(root)
	var rid string
	k.s.conn.QueryRowContext(ctx, "SELECT id FROM outcome_member WHERE op=?", root.op).Scan(&rid)
	if err := k.s.write(ctx, func() error {
		var seq int64
		k.s.conn.QueryRowContext(ctx, "SELECT next_seq-1 FROM meta").Scan(&seq)
		for i := 0; i < 8193; i++ {
			id := fmt.Sprintf("aaaaaaaa-aaaa-4aaa-8aaa-%012x", i)
			if _, err := k.s.conn.ExecContext(ctx, "INSERT INTO exposure VALUES(?,?,?,?,?,?,?,?,?,'local-admission-fence/1')", id, k.o.PinnedGenesisID, testMachine, k.h.credential, k.sc.id, rid, "m1.abcdefghij", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", seq); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_, err := k.s.Snapshot(ctx, ReadRequest{})
	var held *Error
	if !isOwnerBlocked(err, &held) || Code(err) != "lineage_evaluation_required" {
		t.Fatal("incomplete history was not durably held", err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x56}, 32))
	op := k.op(record.KeyOpBody{Op: record.OpDeviceAdd, Subject: sig.KeyRefOf(key.Public().(ed25519.PublicKey), record.RoleDevice, testMachine), Genesis: k.o.PinnedGenesisID, Parents: []string{k.genesis.AdvisoryID}}, k.key, k.key, key)
	if _, err = k.s.Append(ctx, op); err != nil {
		t.Fatal("guard disabled authority", err)
	}
	k.s.Close()
	reopened, err := Open(ctx, k.o)
	if err != nil {
		t.Fatal("guarded normal recovery", err)
	}
	k.s = reopened
	if _, err = k.s.Append(ctx, op); err != nil {
		t.Fatal("guarded immutable control replay", err)
	}
	if _, err = k.s.Snapshot(ctx, ReadRequest{}); err == nil {
		t.Fatal("guard vanished")
	}
}
func isOwnerBlocked(err error, out **Error) bool {
	e, ok := err.(*Error)
	if ok {
		*out = e
	}
	return ok && e.OwnerBlocked
}
func TestKernelNewTableFaultsAreAtomicAndCommitFailurePoisons(t *testing.T) {
	for _, table := range []string{"operation", "outcome_member", "field_completeness", "record_field_projection", "record_taint_evidence", "exposure", "render_attempt", "render_body"} {
		t.Run(table, func(t *testing.T) {
			k := newKernel(t)
			ctx := context.Background()
			var before int
			k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM record").Scan(&before)
			q := "CREATE TRIGGER kernel_fault BEFORE INSERT ON " + table + " BEGIN SELECT RAISE(ABORT,'private error canary'); END"
			if _, err := k.s.conn.ExecContext(ctx, q); err != nil {
				t.Fatal(err)
			}
			// A possible frame creates real receiver-observed taint evidence too.
			args := map[string]any{"goal": "<memory-evidence nonce=\"0123456789abcdef0123\">private payload canary</memory-evidence>"}
			_, err := k.e.Execute(ctx, k.h, k.sc, CallIdentity{SuppliedOpID: "faulted-write"}, commandFor(t, "local.create_task", args), ByteBudget{MaxBytes: 4096})
			if Code(err) != "storage_error" || strings.Contains(err.Error(), "canary") {
				t.Fatal(table, err)
			}
			var after, ops int
			k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM record").Scan(&after)
			k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM operation").Scan(&ops)
			if after != before || ops != 0 {
				t.Fatal("partial signed result", after, before, ops)
			}
			if _, err = k.s.conn.ExecContext(ctx, "DROP TRIGGER kernel_fault"); err != nil {
				t.Fatal(err)
			}
			k.execute("faulted-write", "local.create_task", args)
		})
	}
	t.Run("commit", func(t *testing.T) {
		k := newKernel(t)
		ctx := context.Background()
		for _, q := range []string{"CREATE TABLE disclosure_parent(id INTEGER PRIMARY KEY)", "CREATE TABLE disclosure_child(id INTEGER REFERENCES disclosure_parent(id) DEFERRABLE INITIALLY DEFERRED)", "CREATE TRIGGER kernel_commit AFTER INSERT ON operation BEGIN INSERT INTO disclosure_child VALUES(999); END"} {
			if _, err := k.s.conn.ExecContext(ctx, q); err != nil {
				t.Fatal(err)
			}
		}
		r, err := k.e.Execute(ctx, k.h, k.sc, CallIdentity{SuppliedOpID: "unknown-write"}, commandFor(t, "local.create_task", map[string]any{"goal": "commit candidate"}), ByteBudget{MaxBytes: 4096})
		if Code(err) != "outcome_unknown" || r.engine != nil {
			t.Fatal("unknown commit released result", err)
		}
		if _, err = k.e.Authenticate(ctx, k.proof); Code(err) != "outcome_unknown" {
			t.Fatal("unknown handle still usable", err)
		}
	})
}
func TestKernelListQuerySQLFailureNeverBecomesEmpty(t *testing.T) {
	k := newKernel(t)
	ctx := context.Background()
	k.execute("task", "local.create_task", map[string]any{"goal": "findable source"})
	if _, err := k.s.conn.ExecContext(ctx, "DROP TABLE search"); err != nil {
		t.Fatal(err)
	}
	_, err := k.e.Execute(ctx, k.h, k.sc, CallIdentity{SuppliedOpID: "query-failure"}, commandFor(t, "local.list_tasks", map[string]any{"query": "findable"}), ByteBudget{MaxBytes: 4096})
	if Code(err) != "query_failed" {
		t.Fatal("failed query rendered as empty", err)
	}
	var n int
	k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM operation WHERE tool='local.list_tasks'").Scan(&n)
	if n != 0 {
		t.Fatal("failed query persisted empty outcome")
	}
}
func TestKernelClassifierRebuildPurgesOldProjectionToken(t *testing.T) {
	k := newKernel(t)
	ctx := context.Background()
	r := k.execute("task", "local.create_task", map[string]any{"goal": "<memory-evidence>excluded_canary</memory-evidence>"})
	var id string
	k.s.conn.QueryRowContext(ctx, "SELECT id FROM outcome_member WHERE op=?", r.op).Scan(&id)
	var old int64
	k.s.conn.QueryRowContext(ctx, "SELECT generation FROM record WHERE id=?", id).Scan(&old)
	// Model an older disposable classifier projection, never a completeness fact.
	if _, err := k.s.conn.ExecContext(ctx, "UPDATE record_field_projection SET classifier='old-classifier',class='no_detected_marker' WHERE id=?", id); err != nil {
		t.Fatal(err)
	}
	if _, err := k.s.conn.ExecContext(ctx, "INSERT OR REPLACE INTO projection_job VALUES(?,?)", id, old); err != nil {
		t.Fatal(err)
	}
	if _, err := k.s.conn.ExecContext(ctx, "INSERT OR REPLACE INTO vector VALUES(?,?,'old-model',?)", id, old, []byte("excluded_canary")); err != nil {
		t.Fatal(err)
	}
	before := find(k.snapshot(), id)
	if err := k.s.Reindex(ctx); err != nil {
		t.Fatal(err)
	}
	after := find(k.snapshot(), id)
	if !bytes.Equal(before.HeaderJCS, after.HeaderJCS) || !bytes.Equal(before.BodyJCS, after.BodyJCS) {
		t.Fatal("rebuild resealed source")
	}
	var n int
	k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM vector WHERE id=?", id).Scan(&n)
	if n != 0 {
		t.Fatal("old vector retained")
	}
	if err := k.s.PublishProjection(ctx, JobToken{RecordID: id, Generation: old}, Projection{Model: "old-model", Vector: bytes.Repeat([]byte{1}, 256)}); Code(err) != "stale_projection" {
		t.Fatal("old token published", err)
	}
}
