package syncnode

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	tapredact "github.com/Telara-Labs/TAP-Runtime/discover/redact"
	"sort"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/localpolicy"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	nodesync "github.com/Telara-Labs/telara-memory/contract/internal/node/sync"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
)

// RecordSigner signs a sealed record id with this device's key. It never
// exposes key bytes. The installed daemon supplies the preloaded device key.
type RecordSigner interface {
	KeyID() string
	SignRecordID(string) (record.Signature, error)
}

// maxBatch bounds one exported operation; the push client accepts up to 64.
const maxBatch = 32

// exportRedactor applies the local measured ruleset and, under an installed
// tenant policy, its verified extra shapes. It never accepts caller rules.
type exportRedactor struct{ overlay *localpolicy.Overlay }

func (r exportRedactor) Redact(s string) string {
	if r.overlay != nil {
		return r.overlay.Text(s)
	}
	return localpolicy.Text(s)
}
func (r exportRedactor) Argument(n, s string) string {
	if r.overlay != nil {
		return r.overlay.Argument(n, s)
	}
	return localpolicy.Argument(n, s)
}
func (exportRedactor) Profiles() []string { return nil }
func (r exportRedactor) RedactProfile(profile string, s string) string {
	return tapredact.CurrentRuleset().RedactProfile(profile, r.Redact(s))
}

type candidate struct {
	entry store.Entry
	rec   *record.Record
}

// export builds fresh push-metadata variants for live local session and task
// heads selected by an enabled rule and the grant, seals and signs them, and
// queues one durable operation. It never copies a source body.
func (w *Worker) export(ctx context.Context, p Profile, ob *outbox) (int, error) {
	rules, err := w.state.Rules(ctx)
	if err != nil {
		return 0, err
	}
	enabled := rules[:0]
	for _, r := range rules {
		if r.Enabled && len(r.Repos) > 0 && len(r.Kinds) > 0 {
			enabled = append(enabled, r)
		}
	}
	if len(enabled) == 0 || w.cfg.Signer == nil || w.cfg.Signer.KeyID() == "" {
		return 0, nil
	}
	pol, err := w.cfg.Store.SyncPushPolicy(ctx)
	if err != nil || !pol.DataPush || pol.CancelOutbox {
		return 0, nil
	}
	rs, err := localpolicy.Ruleset()
	if err != nil {
		return 0, err
	}
	redactor := exportRedactor{}
	if pol.Body != nil && len(pol.Body.Redaction.Shapes) > 0 {
		overlay, err := localpolicy.TenantOverlay(pol.Body)
		if err != nil {
			return 0, nil
		}
		redactor.overlay = &overlay
	}
	snap, err := w.cfg.Store.Snapshot(ctx, store.ReadRequest{})
	if err != nil {
		return 0, err
	}
	byID := map[string]candidate{}
	superseded := map[string]bool{}
	for _, e := range snap.Entries {
		r, err := record.Parse(e.HeaderJCS, e.BodyJCS, e.ID)
		if err != nil {
			continue
		}
		byID[e.ID] = candidate{e, r}
		if e.State == "live" {
			for _, prior := range r.Header.Links.Supersedes {
				superseded[e.Owner+"\x00"+string(r.Header.Type)+"\x00"+r.Header.LID+"\x00"+prior] = true
			}
		}
	}
	taken, heads, err := w.exportedSources(ctx, ob.dest)
	if err != nil {
		return 0, err
	}
	var ordered []candidate
	for _, c := range byID {
		ordered = append(ordered, c)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].entry.Sequence < ordered[j].entry.Sequence })
	author := record.Author{MachineID: p.Device, KeyID: w.cfg.Signer.KeyID()}
	var batch []nodesync.SignedRecord
	var rows []queuedRow
	for _, c := range ordered {
		if len(batch) == maxBatch {
			break
		}
		h := c.rec.Header
		if (h.Type != record.KindSession && h.Type != record.KindTask) || h.Red.Profile != record.ProfileLocal || h.Author.MachineID != p.Device || c.entry.State != "live" || c.entry.SignatureStatus != string(sig.StatusVerified) || len(c.entry.BodyJCS) == 0 || taken[c.entry.ID] {
			continue
		}
		if superseded[c.entry.Owner+"\x00"+string(h.Type)+"\x00"+h.LID+"\x00"+c.entry.ID] || !contains(p.Grant.Repos, h.Subj.RepoID) {
			continue
		}
		// A record sealed under a tenant policy is pushable only while a
		// tenant authority governs this node; after logout it stays local.
		if h.Pol != "" && !pol.Governed {
			continue
		}
		var rule *Rule
		for i := range enabled {
			if enabled[i].matches(h.Type, h.Subj.RepoID) {
				rule = &enabled[i]
				break
			}
		}
		if rule == nil {
			continue
		}
		var chunks []*record.Record
		if b, ok := c.rec.Body.(*record.SessionBody); ok {
			complete := true
			for _, id := range b.Chunks {
				chunk, ok := byID[id]
				if !ok || chunk.entry.State != "live" || len(chunk.entry.BodyJCS) == 0 {
					complete = false
					break
				}
				chunks = append(chunks, chunk.rec)
			}
			if !complete {
				continue
			}
		}
		variant, err := record.Export(c.rec, author, heads[string(h.Type)+"\x00"+h.LID], rs, redactor, chunks)
		if err != nil {
			continue
		}
		remote := ""
		if meta, ok := variant.Body.(*record.SessionMetaBody); ok && meta.Repo != nil {
			remote = meta.Repo.Remote
		}
		if !pol.PushAllowed(remote) {
			continue
		}
		signature, err := w.cfg.Signer.SignRecordID(variant.ID)
		if err != nil {
			return 0, err
		}
		signed := nodesync.SignedRecord{Record: variant, Sigs: []record.Signature{signature}}
		if _, err := nodesync.NewOperation("probe", []nodesync.SignedRecord{signed}); err != nil {
			// The exact allowlist refuses this variant before any queueing.
			continue
		}
		batch = append(batch, signed)
		rows = append(rows, queuedRow{RecordID: variant.ID, SourceID: c.entry.ID, LID: h.LID, Kind: string(h.Type), Repo: h.Subj.RepoID, Remote: remote, Authority: rule.authority(), Profile: record.ProfilePushMetadata})
		taken[c.entry.ID] = true
	}
	if len(batch) == 0 {
		return 0, nil
	}
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return 0, err
	}
	opID := hex.EncodeToString(raw[:])
	op, err := nodesync.NewOperation(opID, batch)
	if err != nil {
		return 0, err
	}
	err = w.state.tx(ctx, func(q querier) error {
		// A local scrub may have fenced a source after this batch was
		// prepared. Check the durable sidecar fence under its writer before
		// any copy is stored, including a stale export resuming after scrub.
		for _, r := range rows {
			for _, k := range []fenceKey{{fenceID, r.SourceID}, {fenceID, r.RecordID}, {fenceLID, r.LID}} {
				blocked, err := hasFence(ctx, q, k)
				if err != nil {
					return err
				}
				if blocked {
					return nodesync.ErrCancelled
				}
			}
		}
		if _, err := q.ExecContext(ctx, "INSERT INTO operation VALUES(?,?,?,?,?,0,0,?,'')", opID, ob.dest, op.Bytes(), op.Digest(), statePending, w.state.now().UnixMilli()); err != nil {
			return errStateInvalid
		}
		for i, r := range rows {
			s := batch[i]
			sigs, _ := json.Marshal(s.Sigs)
			if _, err := q.ExecContext(ctx, "INSERT INTO outbox VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", ob.dest, r.RecordID, opID, r.SourceID, r.LID, r.Kind, r.Repo, r.Remote, r.Authority, r.Profile, statePending, pol.PolicyID, s.Record.HeaderJCS, s.Record.BodyJCS, sigs); err != nil {
				return errStateInvalid
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return len(batch), nil
}

// exportedSources returns sources with a non-cancelled row and the current
// export heads per kind and LID, which a new variant supersedes.
func (w *Worker) exportedSources(ctx context.Context, dest string) (map[string]bool, map[string][]*record.Record, error) {
	taken := map[string]bool{}
	heads := map[string][]*record.Record{}
	err := w.state.tx(ctx, func(q querier) error {
		rows, err := q.QueryContext(ctx, "SELECT record_id,source_id,kind,lid,state,header,body FROM outbox WHERE destination=? AND state!=?", dest, stateCancelled)
		if err != nil {
			return errStateInvalid
		}
		defer rows.Close()
		type exported struct {
			id, kind, lid string
			header, body  []byte
			state         string
		}
		var all []exported
		supersededBy := map[string]bool{}
		for rows.Next() {
			var x exported
			var source string
			if rows.Scan(&x.id, &source, &x.kind, &x.lid, &x.state, &x.header, &x.body) != nil {
				return errStateInvalid
			}
			taken[source] = true
			all = append(all, x)
		}
		if rows.Err() != nil {
			return errStateInvalid
		}
		var parsed []*record.Record
		for _, x := range all {
			if (x.state != statePending && x.state != stateComplete) || len(x.header) == 0 || len(x.body) == 0 {
				continue
			}
			r, err := record.Parse(x.header, x.body, x.id)
			if err != nil {
				continue
			}
			parsed = append(parsed, r)
			for _, prior := range r.Header.Links.Supersedes {
				supersededBy[prior] = true
			}
		}
		for _, r := range parsed {
			if !supersededBy[r.ID] {
				key := string(r.Header.Type) + "\x00" + r.Header.LID
				heads[key] = append(heads[key], r)
			}
		}
		return nil
	})
	return taken, heads, err
}

// reconcile drops queued metadata copies whose source is no longer live. A
// pending operation holding such a row is cancelled before it can be sent.
func (w *Worker) reconcile(ctx context.Context, dest string) error {
	type row struct{ op, source, state string }
	var queued []row
	if err := w.state.tx(ctx, func(q querier) error {
		rows, err := q.QueryContext(ctx, "SELECT op_id,source_id,state FROM outbox WHERE destination=? AND (state=? OR (state=? AND body IS NOT NULL))", dest, statePending, stateComplete)
		if err != nil {
			return errStateInvalid
		}
		defer rows.Close()
		for rows.Next() {
			var r row
			if rows.Scan(&r.op, &r.source, &r.state) != nil {
				return errStateInvalid
			}
			queued = append(queued, r)
		}
		if rows.Err() != nil {
			return errStateInvalid
		}
		return nil
	}); err != nil || len(queued) == 0 {
		return err
	}
	snap, err := w.cfg.Store.Snapshot(ctx, store.ReadRequest{})
	if err != nil {
		return err
	}
	live := map[string]bool{}
	for _, e := range snap.Entries {
		live[e.ID] = e.State == "live" && len(e.BodyJCS) > 0
	}
	return w.state.tx(ctx, func(q querier) error {
		var cancel []string
		for _, r := range queued {
			if live[r.source] {
				continue
			}
			if r.state == statePending {
				cancel = append(cancel, r.op)
				continue
			}
			if _, err := q.ExecContext(ctx, "UPDATE outbox SET body=NULL,sigs=NULL WHERE destination=? AND source_id=? AND state=?", dest, r.source, stateComplete); err != nil {
				return errStateInvalid
			}
		}
		return cancelOps(ctx, q, cancel, "source_invalidated")
	})
}
