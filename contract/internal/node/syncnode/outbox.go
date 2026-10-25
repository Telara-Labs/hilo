package syncnode

import (
	"context"
	"database/sql"
	"encoding/json"
	"strconv"
	"strings"
	gosync "sync"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	nodesync "github.com/Telara-Labs/telara-memory/contract/internal/node/sync"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
)

// Store is the subset of the node store the sync adapter reads and the
// control enforcement writes. *store.Store implements it.
type Store interface {
	Snapshot(context.Context, store.ReadRequest) (store.Snapshot, error)
	SyncPushPolicy(context.Context) (store.SyncPolicy, error)
	Append(context.Context, store.SignedRecord) (store.AdmissionResult, error)
	ApplyControl(context.Context, store.SignedRecord) (store.EraseResult, error)
	OfferTenantKeyOperation(context.Context, store.SignedRecord) error
}

// outbox adapts State to the push client for one authenticated destination.
type outbox struct {
	state *State
	store Store
	dest  string
	mu    gosync.Mutex
	// served is the operation most recently returned by Next. The worker runs
	// one round at a time, so it names the operation a refusal applies to.
	served string
}

func newOutbox(st *State, s Store, scope nodesync.Scope) *outbox {
	return &outbox{state: st, store: s, dest: destination(scope)}
}

func (o *outbox) scoped(s nodesync.Scope) bool { return destination(s) == o.dest }

func (o *outbox) lastServed() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.served
}

func (o *outbox) Next(ctx context.Context, s nodesync.Scope, l nodesync.Limits) (*nodesync.Operation, error) {
	if !o.scoped(s) || l.Records < 1 || l.WireBytes < 1 {
		return nil, nodesync.ErrInvalid
	}
	o.mu.Lock()
	o.served = ""
	o.mu.Unlock()
	var raw []byte
	var digest, id string
	err := o.state.tx(ctx, func(q querier) error {
		err := q.QueryRowContext(ctx, "SELECT op_id,raw,digest FROM operation WHERE destination=? AND state=? AND not_before<=? ORDER BY created,op_id LIMIT 1", o.dest, statePending, o.state.now().UnixMilli()).Scan(&id, &raw, &digest)
		if err == sql.ErrNoRows {
			return nil
		}
		if err != nil {
			return errStateInvalid
		}
		return nil
	})
	if err != nil || id == "" {
		return nil, err
	}
	op, err := nodesync.RestoreOperation(raw, digest)
	if err != nil || op.OpID() != id {
		return nil, nodesync.ErrInvalid
	}
	o.mu.Lock()
	o.served = id
	o.mu.Unlock()
	return op, nil
}

type queuedRow struct {
	RecordID, SourceID, LID, Kind, Repo, Remote, Authority, Profile string
}

func opRows(ctx context.Context, q querier, dest, op, digest string) ([]queuedRow, error) {
	var state, stored string
	err := q.QueryRowContext(ctx, "SELECT state,digest FROM operation WHERE op_id=? AND destination=?", op, dest).Scan(&state, &stored)
	if err == sql.ErrNoRows {
		return nil, nodesync.ErrInvalid
	}
	if err != nil {
		return nil, errStateInvalid
	}
	if stored != digest {
		return nil, nodesync.ErrInvalid
	}
	if state != statePending {
		return nil, nil
	}
	rows, err := q.QueryContext(ctx, "SELECT record_id,source_id,lid,kind,repo,remote,authority,profile FROM outbox WHERE op_id=? AND destination=? AND state=? ORDER BY record_id", op, dest, statePending)
	if err != nil {
		return nil, errStateInvalid
	}
	defer rows.Close()
	var out []queuedRow
	for rows.Next() {
		var r queuedRow
		if rows.Scan(&r.RecordID, &r.SourceID, &r.LID, &r.Kind, &r.Repo, &r.Remote, &r.Authority, &r.Profile) != nil {
			return nil, errStateInvalid
		}
		out = append(out, r)
	}
	if rows.Err() != nil {
		return nil, errStateInvalid
	}
	return out, nil
}

// Authorize revalidates every row immediately before a send: the rule still
// exists at the queued version and still matches, the profile is unchanged,
// the source record is live and verified, and current tenant policy permits
// push. Any failure cancels the whole operation and returns false.
func (o *outbox) Authorize(ctx context.Context, s nodesync.Scope, op, digest string) (bool, error) {
	if !o.scoped(s) {
		return false, nodesync.ErrInvalid
	}
	var rows []queuedRow
	if err := o.state.tx(ctx, func(q querier) error {
		var err error
		rows, err = opRows(ctx, q, o.dest, op, digest)
		return err
	}); err != nil {
		return false, err
	}
	if len(rows) == 0 {
		return false, nil
	}
	eligible, reason, err := o.storeEligible(ctx, rows)
	if err != nil {
		return false, err
	}
	ok := false
	err = o.state.tx(ctx, func(q querier) error {
		current, err := opRows(ctx, q, o.dest, op, digest)
		if err != nil {
			return err
		}
		if len(current) != len(rows) {
			eligible, reason = false, "operation_changed"
		}
		if eligible {
			rules, err := readRules(ctx, q)
			if err != nil {
				return err
			}
			for _, r := range current {
				if !ruleAuthorizes(rules, r) {
					eligible, reason = false, "authority_revoked"
					break
				}
			}
		}
		if eligible {
			ok = true
			return nil
		}
		return cancelOps(ctx, q, []string{op}, reason)
	})
	return ok, err
}

func ruleAuthorizes(rules []Rule, r queuedRow) bool {
	if r.Profile != record.ProfilePushMetadata || !strings.HasPrefix(r.Authority, "rule:") {
		return false
	}
	spec := strings.TrimPrefix(r.Authority, "rule:")
	at := strings.LastIndexByte(spec, '@')
	if at < 1 {
		return false
	}
	version, err := strconv.ParseInt(spec[at+1:], 10, 64)
	if err != nil {
		return false
	}
	for _, rule := range rules {
		if rule.ID == spec[:at] {
			return rule.Version == version && rule.Profile == r.Profile && rule.matches(record.Kind(r.Kind), r.Repo)
		}
	}
	return false
}

// storeEligible reads current local state outside the sync transaction. The
// store's own writer serializes this read with admission and invalidation.
func (o *outbox) storeEligible(ctx context.Context, rows []queuedRow) (bool, string, error) {
	pol, err := o.store.SyncPushPolicy(ctx)
	if err != nil {
		return false, "policy_unavailable", nil
	}
	if pol.CancelOutbox || !pol.DataPush {
		return false, "policy_denied", nil
	}
	ids := make([]string, 0, len(rows))
	for _, r := range rows {
		ids = append(ids, r.SourceID)
	}
	snap, err := o.store.Snapshot(ctx, store.ReadRequest{IDs: ids})
	if err != nil {
		return false, "source_unavailable", nil
	}
	live := map[string]bool{}
	for _, e := range snap.Entries {
		live[e.ID] = e.State == "live" && e.SignatureStatus == string(sig.StatusVerified) && len(e.BodyJCS) > 0
	}
	for _, r := range rows {
		if !live[r.SourceID] {
			return false, "source_invalidated", nil
		}
		if !pol.PushAllowed(r.Remote) {
			return false, "policy_denied", nil
		}
	}
	return true, "", nil
}

// Complete persists every verified receipt and terminal unavailable status and
// completes exactly these rows. It never touches either pull cursor.
func (o *outbox) Complete(ctx context.Context, s nodesync.Scope, a nodesync.Acknowledgment) error {
	if !o.scoped(s) {
		return nodesync.ErrInvalid
	}
	return o.state.tx(ctx, func(q querier) error {
		rows, err := opRows(ctx, q, o.dest, a.OpID, a.Digest)
		if err != nil {
			return err
		}
		if len(rows) != len(a.Results) {
			return nodesync.ErrInvalid
		}
		want := map[string]bool{}
		for _, r := range rows {
			want[r.RecordID] = true
		}
		for _, r := range a.Results {
			if !want[r.ID] {
				return nodesync.ErrInvalid
			}
			delete(want, r.ID)
			switch r.Status {
			case "accepted", "accepted-duplicate":
				receipt, err := json.Marshal(r.Receipt)
				if err != nil || r.Receipt == nil {
					return nodesync.ErrInvalid
				}
				var existing []byte
				err = q.QueryRowContext(ctx, "SELECT receipt FROM delivery_receipt WHERE destination=? AND record_id=?", o.dest, r.ID).Scan(&existing)
				if err == nil && string(existing) != string(receipt) {
					return nodesync.ErrReceipt
				}
				if err != nil && err != sql.ErrNoRows {
					return errStateInvalid
				}
				if err == sql.ErrNoRows {
					if _, err = q.ExecContext(ctx, "INSERT INTO delivery_receipt VALUES(?,?,?,?,?)", o.dest, r.ID, receipt, r.HSeq, r.HostedTaskID); err != nil {
						return errStateInvalid
					}
				}
				if _, err = q.ExecContext(ctx, "UPDATE outbox SET state=? WHERE destination=? AND record_id=?", stateComplete, o.dest, r.ID); err != nil {
					return errStateInvalid
				}
			case "unavailable":
				if _, err := q.ExecContext(ctx, "UPDATE outbox SET state=?,body=NULL,sigs=NULL WHERE destination=? AND record_id=?", stateUnavailable, o.dest, r.ID); err != nil {
					return errStateInvalid
				}
			default:
				return nodesync.ErrInvalid
			}
		}
		if _, err := q.ExecContext(ctx, "UPDATE operation SET state=?,raw=x'' WHERE op_id=? AND destination=?", stateComplete, a.OpID, o.dest); err != nil {
			return errStateInvalid
		}
		return nil
	})
}

func (o *outbox) Retry(ctx context.Context, s nodesync.Scope, r nodesync.Retry) error {
	if !o.scoped(s) || r.Attempt < 1 {
		return nodesync.ErrInvalid
	}
	return o.state.tx(ctx, func(q querier) error {
		res, err := q.ExecContext(ctx, "UPDATE operation SET attempt=?,not_before=? WHERE op_id=? AND digest=? AND destination=? AND state=?", r.Attempt, r.NotBefore.UnixMilli(), r.OpID, r.Digest, o.dest, statePending)
		if err != nil {
			return errStateInvalid
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return nodesync.ErrInvalid
		}
		return nil
	})
}

func (o *outbox) Logout(ctx context.Context, s nodesync.Scope) error {
	if !o.scoped(s) {
		return nodesync.ErrInvalid
	}
	return o.state.purgeDestination(ctx, o.dest)
}
