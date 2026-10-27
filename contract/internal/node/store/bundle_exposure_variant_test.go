package store

import (
	"bytes"
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/jcs"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
	"github.com/Telara-Labs/telara-memory/contract/transport"
)

func rootOnlyBundleFacts(t *testing.T, s *Store, ids ...string) [][]byte {
	t.Helper()
	selected := map[string]bool{}
	for _, id := range ids {
		selected[id] = true
	}
	// Multiple local deliveries may encode the same canonical wire fact.
	// Derive the complete selected-root set from the ledger, independently
	// of SelectBundle, and compare exact bytes after wire-set deduplication.
	lines := map[string][]byte{}
	if err := s.write(context.Background(), func() error {
		d, err := s.load(context.Background())
		if err != nil {
			return err
		}
		for id := range selected {
			x := d.byID[id]
			if !available(x) || len(x.recalls) > 0 || len(d.semantic[id]) > 0 {
				t.Fatal("source is not an independent live exposure root", id)
			}
		}
		for _, f := range d.exposures {
			for id := range selected {
				if f.affects[id] {
					t.Fatal("source is affected by an earlier exposure", id)
				}
			}
			if selected[f.root] {
				line, ok := localFact(f, nil)
				if !ok {
					t.Fatal("root fact is not serializable")
				}
				lines[string(line)] = line
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(lines) == 0 {
		t.Fatal("fixture has no root exposure")
	}
	var keys []string
	for line := range lines {
		keys = append(keys, line)
	}
	sort.Strings(keys)
	var facts [][]byte
	for _, line := range keys {
		facts = append(facts, lines[line])
	}
	return facts
}

// Transfer the sender's exact signed controls and current enrolled keyring
// through the verified-bundle admission API. Foreign device controls remain
// forbidden on the ordinary local route. This is a store fixture, not proof
// of signed/encrypted transport or installed acceptance.
func importSenderBundleControls(t *testing.T, sender *Store, target joinedDevice, ids ...string) {
	t.Helper()
	ctx := context.Background()
	selected, err := sender.SelectBundle(ctx, ids)
	if err != nil {
		t.Fatal("sender control selection", err)
	}
	if len(selected.Data) != 0 {
		t.Fatal("control-only sender selection included data", len(selected.Data))
	}
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	var controls []SignedRecord
	for _, control := range selected.Controls {
		if want[control.AdvisoryID] {
			if _, err := target.s.ApplyControl(ctx, control); Code(err) != "unauthorized_record" {
				t.Fatal("foreign control admitted on ordinary local route", err)
			}
			controls = append(controls, control)
			delete(want, control.AdvisoryID)
		}
	}
	if len(want) != 0 || len(controls) == 0 {
		t.Fatal("sender omitted expected signed controls", want)
	}
	review, err := target.s.ReviewBundleControls(ctx, controls)
	if err != nil {
		t.Fatal("receiver control review", err)
	}
	var confirmed []string
	for _, control := range review {
		confirmed = append(confirmed, control.ID)
	}
	if report, err := target.s.ImportBundle(ctx, BundleImport{LocalKeyID: target.KeyID(), Keyring: selected.Keyring, Controls: controls, ConfirmedControls: confirmed}); err != nil || report.Controls != len(controls) {
		t.Fatal("receiver signed control import", report, err)
	}
}

func assertBundleFacts(t *testing.T, got, want [][]byte) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatal("fact count changed", len(got), len(want))
	}
	for _, expected := range want {
		found := false
		for _, actual := range got {
			found = found || bytes.Equal(expected, actual)
		}
		if !found {
			t.Fatal("original fact bytes were omitted or rewritten")
		}
	}
}

// These explicit SQL fixtures test retained historical ledger states. The
// repository acceptance test separately obtains the root from the actual MCP
// builder/release path, without substituting a synthetic task for that proof.
func bundleExposureFixture(t *testing.T, w *world, root, scope, source string, n int) {
	t.Helper()
	var fence int64
	if err := w.s.conn.QueryRowContext(context.Background(), "SELECT max(seq) FROM record").Scan(&fence); err != nil {
		t.Fatal(err)
	}
	id := "aaaaaaaa-aaaa-4aaa-8aaa-" + strings.Repeat("0", 11) + string("0123456789abcdef"[n%16])
	if _, err := w.s.conn.ExecContext(context.Background(), "INSERT INTO exposure VALUES(?,?,?,?,?,?,?,?,?,'local-admission-fence/1')", id, w.o.PinnedGenesisID, testMachine, "fixture", scope, root, source, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", fence); err != nil {
		t.Fatal(err)
	}
}

func governedBundleTask(t *testing.T, w *world, pol string) (SignedRecord, SignedRecord) {
	t.Helper()
	proof := repoProofFixture(t, w, pol, "github.com/acme/widgets")
	w.append(proof)
	r, err := record.Parse(proof.HeaderJCS, proof.BodyJCS, proof.AdvisoryID)
	if err != nil {
		t.Fatal(err)
	}
	task := "77777777-7777-4777-8777-777777777777"
	source := w.signed(record.Header{Type: record.KindTask, LID: record.TaskLID(w.o.PinnedGenesisID, task), Prov: record.ProvMCPExplicit, Pol: pol, Subj: record.Subject{TaskID: task, RepoID: r.Header.Subj.RepoID}, Op: record.H("bundle-root-task")}, &record.TaskBody{Name: "task", Goal: "private body", Status: "active"})
	w.append(source)
	return proof, source
}

func TestBundleExposureRootMetadataForwardingAndErasure(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	recv := joinDevice(t, w)
	last := joinDevice(t, w)
	sign := installTenant(t, w, "tenant-exposure-metadata")
	head := sign(1, pushPolicy(nil))
	w.append(head)
	proof, source := governedBundleTask(t, w, head.AdvisoryID)
	bundleExposureFixture(t, w, source.AdvisoryID, "sc1:"+testMachine+":"+strings.Repeat("a", 32), "m1.abcdefghij", 1)
	facts := rootOnlyBundleFacts(t, w.s, source.AdvisoryID)
	ids := []string{proof.AdvisoryID, source.AdvisoryID}
	e, selected := registerExport(t, w.s, w.o, 3, ids, worldSigner{w.key}, []byte("sealed metadata"))
	defer e.lock.Close()
	if len(selected.Data) != 2 {
		t.Fatal("root-only metadata denied", selected.Excluded)
	}
	assertBundleFacts(t, selected.Facts, facts)
	if err := e.publish(w.s, ids); err != nil {
		t.Fatal(err)
	}
	for _, target := range []joinedDevice{recv, last} {
		installTenant(t, &world{t: t, s: target.s, o: target.o}, "tenant-exposure-metadata")
		if _, err := target.s.Append(ctx, head); err != nil {
			t.Fatal(err)
		}
	}
	if report, err := recv.s.ImportBundle(ctx, BundleImport{LocalKeyID: recv.KeyID(), Keyring: selected.Keyring, Facts: selected.Facts, Data: selected.Data}); err != nil || report.Data != 2 {
		t.Fatal("root metadata import", report, err)
	}
	if err := recv.s.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	recv.s, err = Open(ctx, recv.o)
	if err != nil {
		t.Fatal(err)
	}
	defer recv.s.Close()
	var variantIDs []string
	for _, in := range selected.Data {
		variantIDs = append(variantIDs, in.AdvisoryID)
	}
	forward, carried := registerExport(t, recv.s, recv.o, 4, variantIDs, recv, []byte("forwarded metadata"))
	defer forward.lock.Close()
	if len(carried.Data) != 2 {
		t.Fatal("forwarded metadata denied", carried.Excluded)
	}
	assertBundleFacts(t, carried.Facts, facts)
	if report, err := last.s.ImportBundle(ctx, BundleImport{LocalKeyID: last.KeyID(), Keyring: carried.Keyring, Facts: carried.Facts, Data: carried.Data}); err != nil || report.Data != 2 {
		t.Fatal("forwarded metadata import", report, err)
	}
	control := w.control(912, record.KindErasure, source.AdvisoryID)
	w.append(control)
	for _, target := range []joinedDevice{recv, last} {
		importSenderBundleControls(t, w.s, target, control.AdvisoryID)
		if report, err := target.s.ImportBundle(ctx, BundleImport{LocalKeyID: target.KeyID(), Keyring: carried.Keyring, Facts: carried.Facts, Data: carried.Data}); err != nil || report.Data != 1 {
			t.Fatal("replay admitted erased task metadata", report, err)
		}
		for _, in := range carried.Data {
			r, _ := record.Parse(in.HeaderJCS, in.BodyJCS, in.AdvisoryID)
			if r.Header.Type == record.KindTask {
				entry := find(target.snapshotOf(t), in.AdvisoryID)
				if entry.State == "live" || len(entry.BodyJCS) > 0 {
					t.Fatal("erased original revived its metadata variant")
				}
			}
		}
	}
	if err := forward.publish(recv.s, variantIDs); Code(err) != "bundle_invalidated" {
		t.Fatal("staged forward survived original-root erasure", err)
	}
}

func TestBundleMetadataExposureRestrictionNegatives(t *testing.T) {
	for _, mode := range []string{"affected", "mixed", "unserializable", "imported-source", "frozen-variant"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			w := newWorld(t)
			sign := installTenant(t, w, "tenant-negative-metadata")
			head := sign(1, pushPolicy(nil))
			w.append(head)
			other := w.signed(record.Header{Type: record.KindTask, LID: record.TaskLID(w.o.PinnedGenesisID, "88888888-8888-4888-8888-888888888888"), Prov: record.ProvMCPExplicit, Pol: head.AdvisoryID, Subj: record.Subject{TaskID: "88888888-8888-4888-8888-888888888888"}, Op: record.H("earlier-exposure-root")}, &record.TaskBody{Name: "prior", Goal: "prior", Status: "active"})
			w.append(other)
			scope := "sc1:" + testMachine + ":" + strings.Repeat("b", 32)
			if mode == "affected" || mode == "mixed" {
				bundleExposureFixture(t, w, other.AdvisoryID, scope, "m1.abcdefghij", 2)
			}
			proof, source := governedBundleTask(t, w, head.AdvisoryID)
			if mode == "mixed" || mode == "unserializable" {
				call := "m1.abcdefghij"
				if mode == "unserializable" {
					call = "not-a-call-ref"
				}
				bundleExposureFixture(t, w, source.AdvisoryID, scope, call, 3)
			}
			ids := []string{proof.AdvisoryID, source.AdvisoryID}
			if mode == "imported-source" || mode == "frozen-variant" {
				target := source.AdvisoryID
				var paused inflight
				if mode == "frozen-variant" {
					var sel BundleSelection
					paused, sel = registerExport(t, w.s, w.o, 5, ids, worldSigner{w.key}, []byte("frozen"))
					defer paused.lock.Close()
					for _, in := range sel.Data {
						r, _ := record.Parse(in.HeaderJCS, in.BodyJCS, in.AdvisoryID)
						if r.Header.Type == record.KindTask {
							target = r.ID
						}
					}
					if target == source.AdvisoryID {
						t.Fatal("frozen variant absent")
					}
				}
				fact := bundleImportedFact(t, other.AdvisoryID, []string{target})
				if report, err := w.s.ImportBundle(ctx, BundleImport{LocalKeyID: w.o.PinnedGenesisID, Facts: [][]byte{fact}}); err != nil || report.Facts != 1 {
					t.Fatal("restriction import", report, err)
				}
				if mode == "frozen-variant" {
					if err := paused.publish(w.s, ids); Code(err) != "bundle_invalidated" {
						t.Fatal("new salt evaded frozen-copy restriction", err)
					}
					return
				}
			}
			e, selected := registerExport(t, w.s, w.o, 6, ids, worldSigner{w.key}, []byte("denied task"))
			defer e.lock.Close()
			for _, in := range selected.Data {
				r, _ := record.Parse(in.HeaderJCS, in.BodyJCS, in.AdvisoryID)
				if r.Header.Type == record.KindTask {
					t.Fatal("restricted source acquired metadata exception", mode)
				}
			}
			if excludedReason(selected, source.AdvisoryID) == "" {
				t.Fatal("restricted source missing exclusion", selected.Excluded)
			}
		})
	}
}

func bundleImportedFact(t *testing.T, root string, affected []string) []byte {
	t.Helper()
	f := transport.ExposureFact{OriginMachine: testMachine, ScopeID: "sc1:" + testMachine + ":" + strings.Repeat("c", 32), Boundary: transport.Boundary{Kind: "unknown"}, RecalledID: root, SourceCallOrEvent: transport.ExposureSource{Kind: "call", ID: "m1.abcdefghij"}, AffectsIDs: affected, PendingAttribution: true}
	raw, err := jcs.MarshalRecord(f)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transport.ParseExposure(raw); err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestBundleMetadataOriginChainRestrictions(t *testing.T) {
	for _, mode := range []string{"absent-original", "affected-original", "affected-variant", "two-hops", "missing-full-root", "cycle", "unverified-present", "foreign-present", "mismatched-present-id", "absent-local-origin"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			w := newWorld(t)
			origin := record.H("intentionally absent original")
			meta := func(parent string) *record.Record {
				task := "99999999-9999-4999-8999-999999999999"
				r, err := record.Build(record.Header{Type: record.KindTask, LID: record.TaskLID(w.o.PinnedGenesisID, task), Author: record.Author{MachineID: testMachine, KeyID: w.o.PinnedGenesisID}, At: w.at, Prov: record.ProvDerived, Subj: record.Subject{TaskID: task}, Red: record.Redact{Profile: record.ProfilePushMetadata, Epoch: 1, Fingerprint: strings.Repeat("a", 64)}, Links: record.Links{Origin: parent}}, &record.TaskMetaBody{Status: "active"})
				if err != nil {
					t.Fatal(err)
				}
				return r
			}
			first := meta(origin)
			last := first
			if mode == "absent-local-origin" {
				first.Header.Red.Profile = record.ProfileLocal
			}
			if mode == "two-hops" || mode == "cycle" {
				last = meta(first.ID)
			}
			if err := w.s.write(ctx, func() error {
				d, err := w.s.load(ctx)
				if err != nil {
					return err
				}
				candidates := map[string]transport.BundleRecord{first.ID: {Record: first, ID: first.ID, CompleteSigned: true, Live: true, Selected: true, SelectorIdentity: true, Authorization: transport.BundleAuthorization{ProvenanceKnown: true}}}
				if mode == "cycle" {
					first.Header.Links.Origin = last.ID // impossible signed cycle, refused defensively
				}
				if mode == "unverified-present" || mode == "foreign-present" || mode == "mismatched-present-id" {
					x := &stored{rec: first, owner: w.o.PinnedGenesisID, state: "live", sigStatus: sig.StatusVerified}
					if mode == "unverified-present" {
						x.sigStatus = sig.StatusUnknownSigner
					} else if mode == "foreign-present" {
						x.owner = strings.Repeat("f", 32)
					}
					d.byID[origin] = x
				}
				path, complete, err := d.bundleOrigins(last, candidates)
				if err != nil {
					return err
				}
				badChain := mode == "cycle" || mode == "unverified-present" || mode == "foreign-present" || mode == "mismatched-present-id" || mode == "absent-local-origin"
				if complete == badChain {
					t.Fatal("unexpected chain completeness", mode, complete)
				}
				if badChain {
					return nil
				}
				if mode == "affected-original" || mode == "affected-variant" || mode == "two-hops" || mode == "missing-full-root" {
					target := origin
					if mode == "affected-variant" {
						target = last.ID
					}
					raw := bundleImportedFact(t, record.H("other recalled root"), []string{target})
					f, _ := transport.ParseExposure(raw)
					d.importedFacts = append(d.importedFacts, f)
				}
				restricted, err := d.bundleMetadataRestricted(path, candidates)
				if err != nil {
					return err
				}
				if restricted != (mode != "absent-original") {
					t.Fatal("Origin chain lost restriction", mode, restricted)
				}
				if mode == "missing-full-root" {
					// A selected metadata alias is never a complete signed original
					// root for another record's strict recalled dependency.
					c := candidates[first.ID]
					if !transport.BundleEligible(first.ID, candidates) {
						t.Fatal("positive absent-original metadata control failed")
					}
					c.RecalledRoots = []string{origin}
					candidates[first.ID] = c
					if transport.BundleEligible(first.ID, candidates) {
						t.Fatal("metadata alias filled absent signed root")
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestBundleTranscriptRootMetadataFactLifecycle(t *testing.T) {
	for _, mode := range []string{"direct", "two-hops", "explicit-variant", "explicit-original", "separate-fact", "pending", "unknown", "unverified-association"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			w := newWorld(t)
			recv, last := joinDevice(t, w), joinDevice(t, w)
			sign := installTenant(t, w, "tenant-transcript-root")
			head := sign(1, pushPolicy(nil))
			w.append(head)
			chunk, source := governedSession(w, head.AdvisoryID, "transcript metadata root fixture")
			w.append(chunk)
			w.append(source)
			src, _ := record.Parse(source.HeaderJCS, source.BodyJCS, source.AdvisoryID)
			ch, _ := record.Parse(chunk.HeaderJCS, chunk.BodyJCS, chunk.AdvisoryID)
			ev := ch.Body.(*record.ChunkBody).Events[0]
			seq := ev.Seq
			f := transport.ExposureFact{OriginMachine: testMachine, SessionKey: src.Header.Subj.SessionKey, Boundary: transport.Boundary{Kind: "event", EventID: ev.ID, Seq: &seq}, RecalledID: src.ID, SourceCallOrEvent: transport.ExposureSource{Kind: "event", ID: ev.ID}, PendingAttribution: false}
			ids := []string{src.ID}
			e, initial := registerExport(t, w.s, w.o, 7, ids, worldSigner{w.key}, []byte("initial metadata"))
			defer e.lock.Close()
			if len(initial.Data) != 1 {
				t.Fatal("initial session metadata", initial.Excluded)
			}
			data := append([]SignedRecord(nil), initial.Data...)
			if mode == "two-hops" {
				parent, _ := record.Parse(data[0].HeaderJCS, data[0].BodyJCS, data[0].AdvisoryID)
				h := parent.Header
				h.Links.Origin = parent.ID
				body := *parent.Body.(*record.SessionMetaBody)
				body.Salt = ""
				next, err := record.Build(h, &body)
				if err != nil {
					t.Fatal(err)
				}
				sg, err := sig.SignRecord(w.key, next.ID)
				if err != nil {
					t.Fatal(err)
				}
				// Reverse order exercises complete carried lineage evaluation.
				data = append([]SignedRecord{wire(next, []record.Signature{sg})}, data...)
			}
			switch mode {
			case "explicit-variant":
				f.AffectsIDs = []string{data[0].AdvisoryID}
			case "explicit-original":
				f.AffectsIDs = []string{src.ID}
			case "pending":
				f.PendingAttribution = true
			case "unknown":
				f.Boundary = transport.Boundary{Kind: "unknown"}
				f.PendingAttribution = true
			case "unverified-association":
				f.ScopeID = "sc1:" + testMachine + ":" + strings.Repeat("a", 32)
				f.BindingEvidenceIDs = []string{record.H("unavailable binding")}
			}
			raw, err := jcs.MarshalRecord(f)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = transport.ParseExposure(raw); err != nil {
				t.Fatal(err)
			}
			facts := [][]byte{raw}
			if mode == "separate-fact" {
				other := f
				other.RecalledID = record.H("separate root in same session")
				other.AffectsIDs = []string{src.ID}
				line, err := jcs.MarshalRecord(other)
				if err != nil {
					t.Fatal(err)
				}
				facts = append(facts, line)
			}
			for _, target := range []joinedDevice{recv, last} {
				installTenant(t, &world{t: t, s: target.s, o: target.o}, "tenant-transcript-root")
				if _, err := target.s.Append(ctx, head); err != nil {
					t.Fatal(err)
				}
			}
			// Facts arrive first. Later data must be re-evaluated against them.
			if report, err := recv.s.ImportBundle(ctx, BundleImport{LocalKeyID: recv.KeyID(), Keyring: initial.Keyring, Facts: facts}); err != nil || report.Facts != len(facts) {
				t.Fatal("fact-first admission", report, err)
			}
			positive := mode == "direct" || mode == "two-hops"
			report, err := recv.s.ImportBundle(ctx, BundleImport{LocalKeyID: recv.KeyID(), Data: data})
			if err != nil || positive && report.Data != len(data) || !positive && report.Data != 0 {
				t.Fatal("root session metadata eligibility", mode, report, err)
			}
			if !positive {
				return
			}
			if err := recv.s.Close(); err != nil {
				t.Fatal(err)
			}
			recv.s, err = Open(ctx, recv.o)
			if err != nil {
				t.Fatal(err)
			}
			defer recv.s.Close()
			var carriedIDs []string
			for _, in := range data {
				entry := find(recv.snapshotOf(t), in.AdvisoryID)
				if entry.State != "live" || len(entry.BodyJCS) == 0 {
					t.Fatal("root metadata held after load/reopen", entry.State)
				}
				carriedIDs = append(carriedIDs, in.AdvisoryID)
			}
			forward, carried := registerExport(t, recv.s, recv.o, 8, carriedIDs, recv, []byte("transcript root forward"))
			defer forward.lock.Close()
			if len(carried.Data) != len(data) {
				t.Fatal("root metadata forwarding", carried.Excluded)
			}
			assertBundleFacts(t, carried.Facts, facts)
			if report, err := last.s.ImportBundle(ctx, BundleImport{LocalKeyID: last.KeyID(), Keyring: carried.Keyring, Facts: carried.Facts, Data: carried.Data}); err != nil || report.Data != len(data) {
				t.Fatal("second receiver", report, err)
			}
			if err := last.s.Close(); err != nil {
				t.Fatal(err)
			}
			last.s, err = Open(ctx, last.o)
			if err != nil {
				t.Fatal(err)
			}
			defer last.s.Close()
			again, err := last.s.SelectBundle(ctx, carriedIDs)
			if err != nil || len(again.Data) != len(data) {
				t.Fatal("second receiver reopen", again.Excluded, err)
			}
			assertBundleFacts(t, again.Facts, facts)
			// A different immutable snapshot in the same session stays affected,
			// even when it arrives after the fact and the root-copy exemption.
			if _, err := w.s.ImportBundle(ctx, BundleImport{LocalKeyID: w.o.PinnedGenesisID, Facts: facts}); err != nil {
				t.Fatal(err)
			}
			laterBody := *src.Body.(*record.SessionBody)
			laterBody.Salt, laterBody.Page, laterBody.Chunks = "", 1, nil
			laterHeader := src.Header
			laterHeader.LID = record.SessionLID(src.Header.Subj.SessionKey, testMachine, 1)
			later := w.signed(laterHeader, &laterBody)
			w.append(later)
			control := w.control(913, record.KindErasure, src.ID)
			w.append(control)
			if entry := find(w.snapshot(), later.AdvisoryID); entry.State == "live" {
				t.Fatal("future same-session output lost exposure restriction")
			}
			for _, target := range []joinedDevice{recv, last} {
				importSenderBundleControls(t, w.s, target, control.AdvisoryID)
				// Metadata cannot prove the absent original's complete event
				// membership. Keep the public owner fence while checking the
				// exact retained rows and real body absence below.
				if _, err := target.s.Snapshot(ctx, ReadRequest{}); Code(err) != "bulk_confirmation_required" {
					t.Fatal("metadata erasure lost pending owner fence", err)
				}
				if pending := countRows(t, target.s, "SELECT count(*) FROM erasure_pending WHERE control=?", control.AdvisoryID); pending != 1 {
					t.Fatal("original erasure pending state was not retained", pending)
				}
				for _, in := range data {
					var state string
					var bodies int
					if err := target.s.conn.QueryRowContext(ctx, "SELECT state,(SELECT count(*) FROM record_body WHERE id=?) FROM record WHERE id=?", in.AdvisoryID, in.AdvisoryID).Scan(&state, &bodies); err != nil {
						t.Fatal("erased metadata retained row unavailable", err)
					}
					if state == "live" || bodies != 0 {
						t.Fatal("original erasure did not follow metadata Origin")
					}
				}
			}
			if err := forward.publish(recv.s, carriedIDs); Code(err) != "bundle_invalidated" {
				t.Fatal("root erasure did not cancel staged metadata", err)
			}
		})
	}
}

func TestBundleImportedFactFutureScopeTargets(t *testing.T) {
	ctx := context.Background()
	k := newKernel(t)
	root := k.task(914, "imported scope root")
	k.append(root)
	f, _ := transport.ParseExposure(bundleImportedFact(t, root.AdvisoryID, nil))
	f.ScopeID = k.sc.id
	raw, err := jcs.MarshalRecord(f)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.s.ImportBundle(ctx, BundleImport{LocalKeyID: k.o.PinnedGenesisID, Facts: [][]byte{raw}}); err != nil {
		t.Fatal(err)
	}
	reply := k.execute("future-imported-scope", "local.create_task", map[string]any{"goal": "future explicit output"})
	task := k.taskID(reply)
	var id string
	for _, entry := range k.snapshot().Entries {
		r, _ := record.Parse(entry.HeaderJCS, entry.BodyJCS, entry.ID)
		if r.Header.Type == record.KindTask && r.Header.Subj.TaskID == task {
			id = r.ID
		}
	}
	if id == "" {
		t.Fatal("future scoped task absent")
	}
	k.append(k.control(915, record.KindErasure, root.AdvisoryID))
	if entry := find(k.snapshot(), id); entry.State == "live" {
		t.Fatal("materialized targets dropped future explicit-scope coverage")
	}
}
