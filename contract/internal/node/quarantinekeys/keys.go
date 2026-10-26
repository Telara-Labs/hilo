// Package quarantinekeys extracts bounded identity and lineage from hosted copies.
package quarantinekeys

import (
	nodesync "github.com/Telara-Labs/telara-memory/contract/internal/node/sync"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"strings"
)

// Fence kinds. Task and event fences hold only the task or event ID, a
// superset of the owner-scoped selector, so they err toward dropping.
const (
	ID      = "id"
	LID     = "lid"
	Session = "session"
	Source  = "source"
	Task    = "task"
	Event   = "event"
)

type Key struct{ Kind, Value string }

// Keys is what one quarantined envelope names and copies.
type Keys struct {
	ID       string
	Session  string
	Source   string
	Own      []Key
	Events   []string
	Deps     []string
	Recalled []string
}

// Parse decodes an envelope's identity and dependencies. It reports false
// when they cannot be decided: an envelope that does not open, or a record
// whose body, and with it any manifest or event membership, is absent.
func Parse(env record.Envelope) (Keys, bool) {
	r, err := nodesync.OpenEnvelope(env)
	if err != nil || r.Body == nil {
		return Keys{}, false
	}
	h := r.Header
	k := Keys{ID: r.ID, Session: h.Subj.SessionKey, Source: h.Subj.Source}
	add := func(Kind, v string) {
		if v != "" {
			k.Own = append(k.Own, Key{Kind, v})
		}
	}
	add(ID, r.ID)
	add(LID, h.LID)
	add(Session, h.Subj.SessionKey)
	add(Source, h.Subj.Source)
	add(Task, h.Subj.TaskID)
	k.Deps = append(k.Deps, h.Links.DerivedFrom...)
	if h.Links.Origin != "" {
		k.Deps = append(k.Deps, h.Links.Origin)
	}
	switch b := r.Body.(type) {
	case *record.SessionBody:
		k.Deps = append(k.Deps, b.Chunks...)
	case *record.RollupBody:
		k.Deps = append(k.Deps, b.Covers...)
	case *record.ChunkBody:
		for _, e := range b.Events {
			add(Event, e.ID)
			k.Events = append(k.Events, e.ID)
			for _, rc := range e.Recalled {
				i := strings.LastIndexByte(rc, '@')
				if i < 0 || !record.IsHex64(rc[i+1:]) {
					return Keys{}, false
				}
				k.Recalled = append(k.Recalled, rc[i+1:])
			}
		}
	}
	return k, true
}
