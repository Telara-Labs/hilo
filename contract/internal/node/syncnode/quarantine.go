package syncnode

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/quarantinekeys"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	"github.com/Telara-Labs/telara-memory/contract/record"
)

// Quarantined hosted data is a managed copy: v1 imports none of it, so it is
// kept only while nothing could make it an invalidated copy. The sync database
// holds persistent invalidation fences, written when an erasure or retraction
// is enforced and never removed, not even by logout. Every quarantined
// envelope is checked against them, and against the node store's own tombs and
// bans, both when it arrives and whenever a fence is added, through its whole
// dependency set: links.derived_from, links.origin, session and rollup
// manifests and recalled read-back roots. A record that is dropped becomes a
// fence itself, so its own descendants are dropped too, in every arrival
// order. Anything whose relation to a fence cannot be decided from its
// envelope is dropped conservatively.
const fenceSchema = `
CREATE TABLE IF NOT EXISTS quarantine_fence(kind TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY(kind, value));
CREATE TABLE IF NOT EXISTS quarantine_scrub(destination TEXT PRIMARY KEY);
`

const (
	fenceID      = quarantinekeys.ID
	fenceLID     = quarantinekeys.LID
	fenceSession = quarantinekeys.Session
	fenceSource  = quarantinekeys.Source
	fenceTask    = quarantinekeys.Task
	fenceEvent   = quarantinekeys.Event
)

type fenceKey struct{ kind, value string }
type envKeys struct {
	id, session, source    string
	own                    []fenceKey
	events, deps, recalled []string
}

func keysOf(env record.Envelope) (envKeys, bool) {
	k, ok := quarantinekeys.Parse(env)
	out := envKeys{id: k.ID, session: k.Session, source: k.Source, events: k.Events, deps: k.Deps, recalled: k.Recalled}
	for _, x := range k.Own {
		out.own = append(out.own, fenceKey{x.Kind, x.Value})
	}
	return out, ok
}

// controlFences are the persistent fences an enforced erasure or retraction
// adds. Other controls add none.
func controlFences(ctl *record.Record) []fenceKey {
	var out []fenceKey
	switch b := ctl.Body.(type) {
	case *record.RetractionBody:
		for _, id := range b.IDs {
			out = append(out, fenceKey{fenceID, id})
		}
	case *record.ErasureBody:
		sel := b.Selectors
		for _, v := range sel.IDs {
			out = append(out, fenceKey{fenceID, v})
		}
		for _, v := range sel.LIDs {
			out = append(out, fenceKey{fenceLID, v})
		}
		for _, v := range sel.Sessions {
			out = append(out, fenceKey{fenceSession, v})
		}
		for _, v := range sel.Sources {
			out = append(out, fenceKey{fenceSource, v})
		}
		for _, t := range sel.Tasks {
			out = append(out, fenceKey{fenceTask, t.TaskID})
		}
		for _, e := range sel.Events {
			out = append(out, fenceKey{fenceEvent, e.EventID})
		}
	}
	return out
}

func addFence(ctx context.Context, q querier, k fenceKey) error {
	if k.value == "" {
		return nil
	}
	if _, err := q.ExecContext(ctx, "INSERT OR IGNORE INTO quarantine_fence VALUES(?,?)", k.kind, k.value); err != nil {
		return errStateInvalid
	}
	return nil
}

func hasFence(ctx context.Context, q querier, k fenceKey) (bool, error) {
	var n int
	err := q.QueryRowContext(ctx, "SELECT 1 FROM quarantine_fence WHERE kind=? AND value=?", k.kind, k.value).Scan(&n)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, errStateInvalid
	}
	return true, nil
}

// fenced reports whether k or anything it depends on is fenced, and whether a
// recalled root is, which makes the rest of its session a semantic descendant.
func fenced(ctx context.Context, q querier, k envKeys) (hit, recalled bool, err error) {
	keys := append([]fenceKey(nil), k.own...)
	for _, d := range k.deps {
		keys = append(keys, fenceKey{fenceID, d})
	}
	for _, key := range keys {
		matched, e := hasFence(ctx, q, key)
		if e != nil {
			return false, false, e
		}
		hit = hit || matched
	}
	for _, d := range k.recalled {
		matched, e := hasFence(ctx, q, fenceKey{fenceID, d})
		if e != nil {
			return false, false, e
		}
		recalled = recalled || matched
	}
	return hit || recalled, recalled, nil
}

// storeCheck reports whether the node store invalidates a quarantined
// envelope, or cannot decide that it does not.
type storeCheck func(context.Context, envKeys) bool

// suppressor is implemented by the node store: its durable erasure tombs and
// signed session, source and event bans.
type suppressor interface {
	Suppressed(context.Context, store.SourceOccurrence) (store.Suppression, error)
}

// storeInvalidates checks an envelope's own id and every dependency against
// the store's records, and its session, source and events against the
// store's bans. Any state other than live, and any read the store refuses, is
// treated as invalidating.
func storeInvalidates(s Store, genesis string) storeCheck {
	return func(ctx context.Context, k envKeys) bool {
		seen := map[string]bool{}
		var ids []string
		for _, id := range append(append([]string{k.id}, k.deps...), k.recalled...) {
			if !record.IsHex64(id) {
				return true
			}
			if !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
		if len(ids) > 8192 {
			return true
		}
		reader, ok := s.(interface {
			QuarantineInvalidated(context.Context, []string) (bool, error)
		})
		if !ok {
			return true
		}
		if invalid, err := reader.QuarantineInvalidated(ctx, ids); err != nil || invalid {
			return true
		}
		if k.session == "" && k.source == "" && len(k.events) == 0 {
			return false
		}
		sup, ok := s.(suppressor)
		if !ok {
			return true
		}
		res, err := sup.Suppressed(ctx, store.SourceOccurrence{Owner: genesis, Source: k.source, SessionKey: k.session, EventIDs: k.events})
		return err != nil || res.Suppressed
	}
}

// admit decides one envelope inside a transaction. A dropped envelope's own
// id, when it has one, becomes a fence, and a recalled root also fences its
// session.
func admit(ctx context.Context, q querier, env record.Envelope, check storeCheck) (bool, error) {
	k, ok := keysOf(env)
	drop := !ok || check(ctx, k)
	viaRecall := false
	if ok {
		// Recall exposure must be evaluated even when another invalidation
		// already drops this copy. Otherwise the following session chunks
		// lose their semantic dependency on the erased read-back root.
		hit, recalled, err := fenced(ctx, q, k)
		if err != nil {
			return false, err
		}
		drop, viaRecall = drop || hit, recalled
		if !viaRecall {
			for _, root := range k.recalled {
				if check(ctx, envKeys{id: root}) {
					viaRecall, drop = true, true
					break
				}
			}
		}
	}
	if !drop {
		return true, nil
	}
	id := k.id
	if !ok && record.IsHex64(env.ID) {
		id = env.ID
	}
	if err := addFence(ctx, q, fenceKey{fenceID, id}); err != nil {
		return false, err
	}
	if viaRecall {
		if err := addFence(ctx, q, fenceKey{fenceSession, k.session}); err != nil {
			return false, err
		}
	}
	return false, nil
}

// sweepQuarantine re-decides every quarantined envelope to a fixed point and
// deletes each one that is no longer admissible. Each deletion marks its
// destination for a physical scrub before the next ACK.
func sweepQuarantine(ctx context.Context, q querier, check storeCheck) (int, error) {
	type row struct {
		dest string
		hseq int64
		env  record.Envelope
		ok   bool
	}
	purged := 0
	for {
		rows, err := q.QueryContext(ctx, "SELECT destination,hseq,envelope FROM data_quarantine ORDER BY destination,hseq")
		if err != nil {
			return 0, errStateInvalid
		}
		var all []row
		for rows.Next() {
			var r row
			var raw []byte
			if rows.Scan(&r.dest, &r.hseq, &raw) != nil {
				rows.Close()
				return 0, errStateInvalid
			}
			r.ok = json.Unmarshal(raw, &r.env) == nil
			all = append(all, r)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return 0, errStateInvalid
		}
		changed := false
		for _, r := range all {
			keep := false
			if r.ok {
				if keep, err = admit(ctx, q, r.env, check); err != nil {
					return 0, err
				}
			}
			if keep {
				continue
			}
			if _, err := q.ExecContext(ctx, "DELETE FROM data_quarantine WHERE destination=? AND hseq=?", r.dest, r.hseq); err != nil {
				return 0, errStateInvalid
			}
			if _, err := q.ExecContext(ctx, "INSERT OR IGNORE INTO quarantine_scrub VALUES(?)", r.dest); err != nil {
				return 0, errStateInvalid
			}
			changed = true
			purged++
		}
		if !changed {
			return purged, nil
		}
	}
}

// fenceQuarantine records an enforced control's fences and drops every
// quarantined copy they, or the store's state after the control, invalidate.
func (s *State) fenceQuarantine(ctx context.Context, ctl *record.Record, check storeCheck) error {
	return s.tx(ctx, func(q querier) error {
		for _, k := range controlFences(ctl) {
			if err := addFence(ctx, q, k); err != nil {
				return err
			}
		}
		_, err := sweepQuarantine(ctx, q, check)
		return err
	})
}

// scrubPending reports whether a quarantined copy was deleted since the sync
// database was last established clean.
func (s *State) scrubPending(ctx context.Context) (bool, error) {
	var n int
	err := s.tx(ctx, func(q querier) error {
		if q.QueryRowContext(ctx, "SELECT count(*) FROM quarantine_scrub").Scan(&n) != nil {
			return errStateInvalid
		}
		return nil
	})
	return n > 0, err
}

// establishScrub checkpoints the sync database. Only a clean checkpoint, with
// no reader pinning a superseded page, establishes that no deleted copy
// remains in either file and clears the pending markers, which hold only a
// destination digest.
func (s *State) establishScrub(ctx context.Context) (bool, error) {
	clean, err := s.checkpoint(ctx)
	if err != nil || !clean {
		return false, err
	}
	err = s.tx(ctx, func(q querier) error {
		if _, err := q.ExecContext(ctx, "DELETE FROM quarantine_scrub"); err != nil {
			return errStateInvalid
		}
		return nil
	})
	return err == nil, err
}
