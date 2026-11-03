package store

import (
	"context"
	"encoding/json"
	"reflect"
	"sort"
	"sync"
	"testing"

	"github.com/Telara-Labs/hilo/contract/record"
)

var testIssued = struct {
	sync.Mutex
	tokens map[string]map[string]string
}{tokens: map[string]map[string]string{}}

func (k *kernelWorld) issued(label string) string {
	k.t.Helper()
	testIssued.Lock()
	defer testIssued.Unlock()
	aliases := testIssued.tokens[k.o.Dir+"/"+k.h.credential]
	if aliases == nil {
		aliases = map[string]string{}
		testIssued.tokens[k.o.Dir+"/"+k.h.credential] = aliases
	}
	if token := aliases[label]; token != "" {
		return token
	}
	pool, err := k.e.IssueOperationTokens(context.Background(), k.h)
	if err != nil {
		k.t.Fatal(err)
	}
	used := map[string]bool{}
	for _, token := range aliases {
		used[token] = true
	}
	for _, token := range pool {
		if !used[token] {
			aliases[label] = token
			return token
		}
	}
	k.t.Fatal("test operation pool exhausted")
	return ""
}

// Reauthor a NEW v3 revision in a fixture. This never changes a transferred seal.
func freshFixtureBody(body any) any {
	copy := reflect.New(reflect.TypeOf(body).Elem())
	b, _ := json.Marshal(body)
	defer clear(b)
	_ = json.Unmarshal(b, copy.Interface())
	if field := copy.Elem().FieldByName("Salt"); field.IsValid() {
		field.SetString("")
	}
	return copy.Interface()
}

func (w *world) completeErasure(b *record.ErasureBody) {
	b.EventCoverage = "complete"
	sort.Strings(b.Selectors.IDs)
	sort.Strings(b.Selectors.LIDs)
	sort.Strings(b.Selectors.Sessions)
	sort.Strings(b.Selectors.Sources)
	err := w.s.write(context.Background(), func() error {
		d, err := w.s.load(context.Background())
		if err != nil {
			return err
		}
		seeds := map[string]bool{}
		for _, id := range b.Selectors.IDs {
			seeds[id] = true
		}
		events := map[[3]string]bool{}
		for _, sel := range b.Selectors.Events {
			events[[3]string{sel.Owner, sel.SessionKey, sel.EventID}] = true
		}
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
				if selected {
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
		}
		for key := range events {
			b.Selectors.Events = append(b.Selectors.Events, record.EventSelector{Owner: key[0], SessionKey: key[1], EventID: key[2]})
		}
		sort.Slice(b.Selectors.Events, func(i, j int) bool {
			a, z := b.Selectors.Events[i], b.Selectors.Events[j]
			return a.Owner+a.SessionKey+a.EventID < z.Owner+z.SessionKey+z.EventID
		})
		// Existing explicit selectors are not duplicated by fixture completion.
		unique := b.Selectors.Events[:0]
		for _, v := range b.Selectors.Events {
			if len(unique) == 0 || unique[len(unique)-1] != v {
				unique = append(unique, v)
			}
		}
		b.Selectors.Events = unique
		return nil
	})
	if err != nil {
		w.t.Fatal(err)
	}
}

// Legacy late-body tests inspect bookkeeping while v3 correctly blocks ALL
// disclosure for incomplete signed event coverage. Explicitly assert that hold,
// then read only content-free SQL metadata; this never substitutes a data read.
func fixturePendingMetadata(t *testing.T, s *Store) Snapshot {
	t.Helper()
	var pending int
	if s.conn.QueryRowContext(context.Background(), "SELECT count(*) FROM erasure_pending").Scan(&pending) != nil || pending == 0 {
		t.Fatal("no explicit pending erasure")
	}
	var out Snapshot
	if s.conn.QueryRowContext(context.Background(), "SELECT generation FROM meta WHERE singleton=1").Scan(&out.Generation) != nil {
		t.Fatal("metadata unavailable")
	}
	rows, err := s.conn.QueryContext(context.Background(), "SELECT r.id,r.header,r.sigs,r.owner,r.state,r.sig_status,r.seq,r.generation FROM record r ORDER BY r.seq")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var e Entry
		var signatures []byte
		if rows.Scan(&e.ID, &e.HeaderJCS, &signatures, &e.Owner, &e.State, &e.SignatureStatus, &e.Sequence, &e.Generation) != nil {
			t.Fatal("metadata unavailable")
		}
		_ = json.Unmarshal(signatures, &e.Sigs)
		e.AdvisoryID = e.ID
		out.Entries = append(out.Entries, e)
	}
	if rows.Err() != nil {
		t.Fatal(rows.Err())
	}
	return out
}
