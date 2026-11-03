package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/sig"
)

type worldSigner struct{ key ed25519.PrivateKey }

func (s worldSigner) KeyID() string { return sig.KeyID(s.key.Public().(ed25519.PublicKey)) }
func (s worldSigner) SignRecordID(id string) (record.Signature, error) {
	return sig.SignRecord(s.key, id)
}

func TestEraseExactPurgesClosureAndScrubsPhysicalBytes(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	token := "eraseexactcanaryquokkamarmalade"
	a := seedFreshCheckpoint(w, token)
	absent := strings.Repeat("ab", 32)
	receipt, err := w.s.EraseExact(ctx, EraseRequest{IDs: []string{a.AdvisoryID, absent}}, worldSigner{w.key})
	if err != nil {
		t.Fatal(err)
	}
	if !record.IsHex64(receipt.Control) || receipt.Reason != "user_request" || receipt.Pending || receipt.Physical != "pending" || len(receipt.Requested) != 2 {
		t.Fatalf("receipt %+v", receipt)
	}
	status := map[string]string{}
	for _, r := range receipt.Requested {
		status[r.ID] = r.Status
	}
	if status[a.AdvisoryID] != "erased" || status[absent] != "not_present" {
		t.Fatalf("statuses %+v", receipt.Requested)
	}
	if e := find(w.snapshot(), a.AdvisoryID); e.State != "invalidated" || len(e.BodyJCS) != 0 {
		t.Fatalf("erased record still live %+v", e.State)
	}
	contains := func(xs []string, x string) bool {
		for _, v := range xs {
			if v == x {
				return true
			}
		}
		return false
	}
	jobs := func(d Diagnostics) []string {
		var out []string
		for _, j := range d.Scrub.Jobs {
			out = append(out, j.Control)
		}
		return out
	}
	pending, err := w.s.PendingScrubs(ctx)
	if err != nil || !contains(pending, receipt.Control) {
		t.Fatal("scrub job not durable", pending, err)
	}
	diag, err := Inspect(ctx, w.o.Dir)
	if err != nil || diag.Scrub.Pending != int64(len(pending)) || !contains(jobs(diag), receipt.Control) {
		t.Fatalf("inspect before scrub %+v %v", diag.Scrub, err)
	}
	done, err := w.s.Scrub(ctx, receipt.Control)
	if err != nil || done.State != "complete" {
		t.Fatal("scrub", done, err)
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		b, err := os.ReadFile(w.s.path + suffix)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(b, []byte(token)) {
			t.Fatal("planted bytes remain in", suffix)
		}
	}
	diag, err = Inspect(ctx, w.o.Dir)
	if err != nil || contains(jobs(diag), receipt.Control) || diag.Scrub.Complete < 1 || diag.Scrub.ErasurePending != 0 {
		t.Fatalf("inspect after scrub %+v %v", diag.Scrub, err)
	}
	if pending, err = w.s.PendingScrubs(ctx); err != nil || contains(pending, receipt.Control) {
		t.Fatal(pending, err)
	}
	// A repeated erasure is a fresh durable control and reports no new effect.
	again, err := w.s.EraseExact(ctx, EraseRequest{IDs: []string{a.AdvisoryID}}, worldSigner{w.key})
	if err != nil || again.Control == receipt.Control || again.Requested[0].Status != "already_invalidated" {
		t.Fatalf("repeat %+v %v", again, err)
	}
}

func TestEraseExactRefusesInvalidRequestsWithoutWriting(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	before := w.snapshot().Generation
	id := strings.Repeat("cd", 32)
	for name, req := range map[string]EraseRequest{
		"empty":     {},
		"malformed": {IDs: []string{"not-an-id"}},
		"duplicate": {IDs: []string{id, id}},
		"reason":    {IDs: []string{id}, Reason: "because"},
	} {
		if _, err := w.s.EraseExact(ctx, req, worldSigner{w.key}); Code(err) != "invalid_arguments" {
			t.Fatal(name, err)
		}
	}
	if _, err := w.s.EraseExact(ctx, EraseRequest{IDs: []string{id}}, nil); Code(err) != "signing_unavailable" {
		t.Fatal("nil signer", err)
	}
	// A key outside the pinned keyring cannot author an accepted control.
	stranger := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{77}, 32))
	if _, err := w.s.EraseExact(ctx, EraseRequest{IDs: []string{id}}, worldSigner{stranger}); err == nil {
		t.Fatal("foreign signer accepted")
	}
	if got := w.snapshot().Generation; got != before {
		t.Fatal("refused erasure wrote state", before, got)
	}
}

func TestInspectIsReadOnlyAndReportsSigningBacklog(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	seedFreshCheckpoint(w, "inspect fixture")
	// Mark one record unsigned-local through SQL to plant a backlog condition
	// without a signing key; Inspect must report it and change nothing.
	if _, err := w.s.conn.ExecContext(ctx, "UPDATE record SET sig_status='unsigned-local' WHERE rowid=(SELECT max(rowid) FROM record)"); err != nil {
		t.Fatal(err)
	}
	stat := func() (int64, time.Time) {
		info, err := os.Stat(w.s.path)
		if err != nil {
			t.Fatal(err)
		}
		return info.Size(), info.ModTime()
	}
	size, mod := stat()
	diag, err := Inspect(ctx, w.o.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if diag.SigningBacklog != 1 || diag.Records < 2 || diag.SignatureState["verified"] < 1 || diag.Policy.Installed || diag.Policy.Freshness != "none" {
		t.Fatalf("%+v", diag)
	}
	if s2, m2 := stat(); s2 != size || !m2.Equal(mod) {
		t.Fatal("inspect modified the database")
	}
	if _, err = Inspect(ctx, t.TempDir()); err != ErrNoDatabase {
		t.Fatal("missing database", err)
	}
}

func TestInspectReportsPolicyStaleAndKill(t *testing.T) {
	k := newKernel(t)
	ctx := context.Background()
	_, build := tenantFixture(t, k)
	if _, err := k.s.Append(ctx, build(1, &record.PolicyBody{})); err != nil {
		t.Fatal(err)
	}
	diag, err := Inspect(ctx, k.o.Dir)
	if err != nil || !diag.Policy.Installed || diag.Policy.Seq != 1 || diag.Policy.Freshness != "fresh" || diag.Policy.Stale || diag.Policy.KillSync || !diag.Policy.DataPush {
		t.Fatalf("fresh %+v %v", diag.Policy, err)
	}
	stale := &record.PolicyBody{RefreshAfter: time.Now().UnixMilli() - 1, Kill: record.PolicyKill{Sync: true}}
	if _, err = k.s.Append(ctx, build(2, stale)); err != nil {
		t.Fatal(err)
	}
	diag, err = Inspect(ctx, k.o.Dir)
	if err != nil || diag.Policy.Seq != 2 || diag.Policy.Freshness != "refresh-due" || !diag.Policy.Stale || diag.Policy.FailClosed || !diag.Policy.KillSync || diag.Policy.DataPush || diag.Policy.DataPull {
		t.Fatalf("stale kill %+v %v", diag.Policy, err)
	}
}

func TestInspectReadsWhileWriterHoldsTheStore(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	seedFreshCheckpoint(w, "concurrent fixture")
	if _, err := Inspect(ctx, w.o.Dir); err != nil {
		t.Fatal(err)
	}
	// The writer remains fully usable after an inspection.
	if _, err := w.s.EraseExact(ctx, EraseRequest{IDs: []string{strings.Repeat("ef", 32)}}, worldSigner{w.key}); err != nil {
		t.Fatal(err)
	}
}
