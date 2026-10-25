package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"sort"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/record"
)

// ControlSigner signs an already built record id with the active device key.
// It never exposes key bytes.
type ControlSigner interface {
	KeyID() string
	SignRecordID(string) (record.Signature, error)
}

// EraseRequest is an owner-issued permanent erasure of exact record ids. Other
// selector kinds have unbounded future effect and require the bulk
// confirmation path, which this store does not provide.
type EraseRequest struct {
	IDs    []string
	Reason string
}

// ErasedTarget is one requested id and what this control did to it. Kind is
// the surviving header kind; no body or content is reported.
type ErasedTarget struct {
	ID     string `json:"id"`
	Kind   string `json:"kind,omitempty"`
	Status string `json:"status"` // erased | already_invalidated | not_present | control_unaffected
}

// EraseReceipt is the durable outcome of one exact-id erasure. Physical is
// "pending" until Scrub reports complete for Control.
type EraseReceipt struct {
	Control    string         `json:"control"`
	Sequence   int64          `json:"sequence"`
	Generation int64          `json:"generation"`
	Reason     string         `json:"reason"`
	Requested  []ErasedTarget `json:"requested"`
	Closure    []ErasedTarget `json:"closure"` // dependent records invalidated with the request
	EventBans  int            `json:"event_bans"`
	Pending    bool           `json:"erasure_pending"`
	Physical   string         `json:"physical"`
}

// EraseExact resolves the requested ids and their copied closure, enumerates
// every contained event namespace, signs one complete erasure control and
// admits it, all under one writer transaction. Bodies are purged only by the
// ordinary admission engine; this method never deletes rows itself.
func (s *Store) EraseExact(ctx context.Context, req EraseRequest, signer ControlSigner) (EraseReceipt, error) {
	reason := req.Reason
	if reason == "" {
		reason = "user_request"
	}
	switch reason {
	case "user_request", "redaction_miss", "device_compromise", "retention_policy":
	default:
		return EraseReceipt{}, failure("invalid_arguments")
	}
	ids := append([]string(nil), req.IDs...)
	sort.Strings(ids)
	if len(ids) == 0 || len(ids) > record.MaxErasureEntries {
		return EraseReceipt{}, failure("invalid_arguments")
	}
	for i, id := range ids {
		if !record.IsHex64(id) || i > 0 && ids[i-1] == id {
			return EraseReceipt{}, failure("invalid_arguments")
		}
	}
	if signer == nil || !record.IsKeyID(signer.KeyID()) {
		return EraseReceipt{}, failure("signing_unavailable")
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return EraseReceipt{}, failure("entropy_unavailable")
	}
	out := EraseReceipt{Reason: reason, Physical: "pending"}
	err := s.write(ctx, func() error {
		d, err := s.load(ctx)
		if err != nil {
			return err
		}
		prior := map[string]string{}
		for _, x := range d.records {
			prior[x.rec.ID] = x.state
		}
		before := map[string]string{}
		for _, id := range ids {
			if x := d.byID[id]; x == nil {
				before[id] = "not_present"
			} else if x.rec.Header.Type.IsControl() {
				before[id] = "control_unaffected"
			} else if x.state == "invalidated" {
				before[id] = "already_invalidated"
			}
		}
		events := closureEvents(d, ids)
		if len(ids)+len(events) > record.MaxErasureEntries {
			return failure("erasure_too_large")
		}
		body := &record.ErasureBody{EventCoverage: "complete", Reason: reason, Selectors: record.Selectors{IDs: ids, Events: events}}
		h := record.Header{Type: record.KindErasure, Prov: record.ProvUser, Author: record.Author{MachineID: s.opts.LocalMachineID, KeyID: signer.KeyID()}, At: time.Now().UnixMilli(), Red: record.Redact{Profile: record.ProfileLocal}}
		if h.LID, err = record.ControlLID(record.KindErasure, signer.KeyID(), hex.EncodeToString(nonce)); err != nil {
			return failure("invalid_record")
		}
		r, err := record.Build(h, body)
		if err != nil {
			return failure("invalid_record")
		}
		sg, err := signer.SignRecordID(r.ID)
		if err != nil {
			return failure("signing_unavailable")
		}
		// Admission re-parses the exact wire bytes, as for any other control.
		parsed, signatures, err := parse(SignedRecord{HeaderJCS: r.HeaderJCS, BodyJCS: r.BodyJCS, Sigs: []record.Signature{sg}, AdvisoryID: r.ID})
		if err != nil {
			return err
		}
		admitted, err := s.appendLocked(ctx, parsed, signatures)
		if err != nil {
			return err
		}
		out.Control, out.Sequence, out.Generation, out.EventBans = admitted.ID, admitted.Sequence, admitted.Generation, len(events)
		effect := map[string]bool{}
		rows, err := s.conn.QueryContext(ctx, "SELECT target FROM erasure_effect WHERE control=? ORDER BY target", admitted.ID)
		if err != nil {
			return failure("storage_error")
		}
		var targets []string
		for rows.Next() {
			var t string
			if rows.Scan(&t) != nil {
				rows.Close()
				return failure("storage_error")
			}
			effect[t] = true
			targets = append(targets, t)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return failure("storage_error")
		}
		requested := map[string]bool{}
		for _, id := range ids {
			requested[id] = true
			status := before[id]
			if status == "" {
				status = "already_invalidated"
				if effect[id] {
					status = "erased"
				}
			}
			kind, err := s.headerKind(ctx, id)
			if err != nil {
				return err
			}
			out.Requested = append(out.Requested, ErasedTarget{ID: id, Kind: kind, Status: status})
		}
		for _, t := range targets {
			if requested[t] {
				continue
			}
			kind, err := s.headerKind(ctx, t)
			if err != nil {
				return err
			}
			status := "erased"
			if prior[t] == "invalidated" {
				status = "already_invalidated"
			}
			out.Closure = append(out.Closure, ErasedTarget{ID: t, Kind: kind, Status: status})
		}
		var pending int
		if s.conn.QueryRowContext(ctx, "SELECT count(*) FROM erasure_pending WHERE control=?", admitted.ID).Scan(&pending) != nil {
			return failure("storage_error")
		}
		out.Pending = pending > 0
		return nil
	})
	if err != nil {
		return EraseReceipt{}, err
	}
	return out, nil
}

// closureEvents saturates the requested ids over copied dependencies and
// shared event membership, returning every known contained event namespace.
func closureEvents(d *databaseState, ids []string) []record.EventSelector {
	seeds := map[string]bool{}
	for _, id := range ids {
		seeds[id] = true
	}
	events := map[[3]string]bool{}
	for change := true; change; {
		change = false
		for _, x := range d.records {
			if x.rec.Header.Type.IsControl() {
				continue
			}
			selected := seeds[x.rec.ID]
			for _, p := range x.deps {
				selected = selected || seeds[p]
			}
			for _, ev := range x.events {
				selected = selected || events[[3]string{x.owner, x.rec.Header.Subj.SessionKey, ev}]
			}
			if !selected {
				continue
			}
			if !seeds[x.rec.ID] {
				seeds[x.rec.ID] = true
				change = true
			}
			for _, ev := range x.events {
				key := [3]string{x.owner, x.rec.Header.Subj.SessionKey, ev}
				if !events[key] {
					events[key] = true
					change = true
				}
			}
		}
	}
	out := make([]record.EventSelector, 0, len(events))
	for k := range events {
		out = append(out, record.EventSelector{Owner: k[0], SessionKey: k[1], EventID: k[2]})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		return a.Owner+"/"+a.SessionKey+"/"+a.EventID < b.Owner+"/"+b.SessionKey+"/"+b.EventID
	})
	return out
}

func (s *Store) headerKind(ctx context.Context, id string) (string, error) {
	var h []byte
	err := s.conn.QueryRowContext(ctx, "SELECT header FROM record WHERE id=?", id).Scan(&h)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", failure("storage_error")
	}
	var v struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(h, &v) != nil {
		return "", failure("corrupt_database")
	}
	return v.Type, nil
}

// PendingScrubs lists durable scrub jobs that have not reached a clean receipt.
func (s *Store) PendingScrubs(ctx context.Context) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, failure("closed")
	}
	rows, err := s.conn.QueryContext(ctx, "SELECT control FROM scrub_job WHERE state!='complete' ORDER BY control LIMIT 8193")
	if err != nil {
		return nil, failure("storage_error")
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var c string
		if rows.Scan(&c) != nil {
			return nil, failure("storage_error")
		}
		out = append(out, c)
	}
	if rows.Err() != nil {
		return nil, failure("storage_error")
	}
	return out, nil
}
