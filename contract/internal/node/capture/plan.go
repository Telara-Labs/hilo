package capture

import (
	"bytes"
	"crypto/ed25519"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	"github.com/Telara-Labs/telara-memory/contract/jcs"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
)

type baselineEvent struct {
	event  record.Event
	source string
}
type priorChunk struct {
	id     string
	record *record.Record
	events []record.Event
}
type eventDecision struct {
	event   record.Event
	source  string
	mint    bool
	parents []string
}

func parseStored(in store.SignedRecord) (*record.Record, error) {
	r, err := record.Parse(in.HeaderJCS, in.BodyJCS, in.AdvisoryID)
	if err != nil {
		return nil, hold("history_invalid")
	}
	return r, nil
}
func originalFrontier(h store.CaptureEventHistory, b baselineEvent) bool {
	copyFound := false
	for _, v := range h.Copies {
		if v.RecordID == b.source && v.Event.Revision == b.event.Revision && v.Live && v.Admissible {
			copyFound = true
			break
		}
	}
	if !copyFound || !h.Facts.CurrentSources[b.source] {
		return false
	}
	for _, p := range h.Facts.Presence {
		if p.RecordID == b.source && p.EventID == b.event.ID && p.Revision == b.event.Revision && p.Admissible && equalStrings(p.Replaces, b.event.Replaces) {
			return true
		}
	}
	return false
}
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func decisions(events []record.Event, baseline map[string]baselineEvent, hist map[string]store.CaptureEventHistory) ([]eventDecision, error) {
	out := make([]eventDecision, 0, len(events))
	for _, e := range events {
		h, ok := hist[e.ID]
		if !ok || h.Banned || !h.CompleteFrontier || h.Pending {
			return nil, hold("history_incomplete")
		}
		old, knownSource := baseline[e.ID]
		if knownSource {
			if !originalFrontier(h, old) {
				return nil, hold("baseline_unavailable")
			}
			a, err := record.EventPayload(e)
			if err != nil {
				return nil, hold("event_payload")
			}
			b, err := record.EventPayload(old.event)
			if err != nil {
				clear(a)
				return nil, hold("event_payload")
			}
			same := bytes.Equal(a, b)
			clear(a)
			clear(b)
			if same {
				out = append(out, eventDecision{event: old.event, source: old.source})
				continue
			}
		} else if h.KnownPresence {
			return nil, hold("ambiguous_source_baseline")
		}
		parents := append([]string(nil), h.MaximalRevisionIDs...)
		sort.Strings(parents)
		if len(parents) > 8 || (h.KnownPresence && len(parents) == 0) {
			return nil, hold("history_incomplete")
		}
		for i, p := range parents {
			if !record.IsHex64(p) || (i > 0 && p == parents[i-1]) {
				return nil, hold("history_incomplete")
			}
		}
		if !h.KnownPresence && len(parents) != 0 {
			return nil, hold("history_incomplete")
		}
		out = append(out, eventDecision{event: e, mint: true, parents: parents})
	}
	return out, nil
}

// Dry canonical sizing uses fixed-width public placeholders, not real salts,
// entropy, revision IDs or hashes. It never leaves the producer process.
func partition(ds []eventDecision) ([][]eventDecision, error) {
	template, err := jcs.MarshalRecord(&record.ChunkBody{Salt: strings.Repeat("A", 22), Events: []record.Event{}})
	if err != nil {
		return nil, hold("event_payload")
	}
	overhead := len(template)
	var groups [][]eventDecision
	var current []eventDecision
	groupBytes, total := overhead, 0
	for _, d := range ds {
		e := d.event
		if d.mint {
			e.Salt = strings.Repeat("A", 22)
			e.Revision = strings.Repeat("0", 64)
			e.Replaces = d.parents
		}
		raw, err := jcs.MarshalRecord(e)
		if err != nil {
			return nil, hold("event_payload")
		}
		n := len(raw)
		clear(raw)
		if overhead+n > record.MaxBodyBytes {
			return nil, hold("event_size")
		}
		next := groupBytes + n
		if len(current) > 0 {
			next++
		}
		if len(current) == record.MaxChunkEvents || next > record.MaxBodyBytes {
			total += groupBytes + record.MaxHeaderBytes
			groups = append(groups, current)
			current = nil
			groupBytes = overhead
			next = overhead + n
		}
		if total+next+record.MaxHeaderBytes > 16<<20 || len(groups) >= 64 {
			return nil, hold("plan_limit")
		}
		current = append(current, d)
		groupBytes = next
	}
	if len(current) > 0 {
		groups = append(groups, current)
	}
	return groups, nil
}

func (p *Pipeline) produce(tx *store.CaptureTxn, q store.CaptureRequest, batch preparedBatch, events []record.Event, h *openedUnitHandle) (store.CommitPlan, error) {
	var empty store.CommitPlan
	c, err := tx.Context()
	if err != nil {
		return empty, hold("transaction_expired")
	}
	if c.OwnerGenesis != p.config.OwnerGenesis || c.MachineID != p.config.MachineID || c.CheckedAuthorKeyID != p.keys.keyID || c.ProgressVersion != q.ExpectedVersion {
		return empty, hold("authority_changed")
	}
	q.PolicyID = c.PolicyID
	progress, err := tx.Progress()
	if err != nil {
		return empty, hold("transaction_expired")
	}
	if progress.Range.LastExclusive > q.Range.LastExclusive {
		return empty, hold("source_regression")
	}
	prior, err := tx.PriorSource()
	if err != nil {
		return empty, hold("history_unavailable")
	}
	pages, err := tx.SessionPages()
	if err != nil {
		return empty, hold("history_unavailable")
	}
	history, err := tx.Events(q.EventIDs)
	if err != nil {
		return empty, hold("history_unavailable")
	}
	baseline := map[string]baselineEvent{}
	chunks := []priorChunk{}
	currentIDs := map[string]bool{}
	minSeq := map[string]int64{}
	for _, e := range events {
		currentIDs[e.ID] = true
	}
	for _, old := range prior {
		if old.Availability != "available" {
			return empty, hold("baseline_unavailable")
		}
		r, err := parseStored(old.SignedRecord)
		if err != nil {
			return empty, err
		}
		body, ok := r.Body.(*record.ChunkBody)
		if !ok || r.Header.Subj.SessionKey != q.Occurrence.SessionKey || r.Header.Subj.Source != q.Occurrence.Source {
			return empty, hold("history_invalid")
		}
		chunks = append(chunks, priorChunk{id: r.ID, record: r, events: body.Events})
		for _, e := range body.Events {
			if !currentIDs[e.ID] {
				return empty, hold("source_regression")
			}
			if old, exists := baseline[e.ID]; exists {
				if !reflect.DeepEqual(old.event, e) {
					return empty, hold("ambiguous_source_baseline")
				}
			} else {
				baseline[e.ID] = baselineEvent{event: e, source: r.ID}
			}
		}
	}
	for _, h := range history {
		for _, copy := range h.Copies {
			if copy.Live && copy.Admissible {
				if seq, ok := minSeq[copy.RecordID]; !ok || copy.Event.Seq < seq {
					minSeq[copy.RecordID] = copy.Event.Seq
				}
			}
		}
	}
	ds, err := decisions(events, baseline, history)
	if err != nil {
		return empty, err
	}
	groups, err := partition(ds)
	if err != nil {
		return empty, err
	}
	// Validate page ancestry/membership BEFORE acquiring any secret lease.
	type oldPage struct {
		ref store.CapturePage
		r   *record.Record
		b   *record.SessionBody
	}
	oldPages := map[int64]oldPage{}
	memberSet := map[string]bool{}
	for _, page := range pages {
		if page.Availability != "available" {
			return empty, hold("page_unavailable")
		}
		r, err := parseStored(page.SignedRecord)
		if err != nil {
			return empty, err
		}
		body, ok := r.Body.(*record.SessionBody)
		if !ok || body.Page != page.Page || body.NativeID != batch.nativeSession || body.NativeIDKind != record.NativeGlobal || r.Header.Subj.SessionKey != q.Occurrence.SessionKey || r.Header.Subj.Source != q.Occurrence.Source || r.Header.Author.MachineID != p.config.MachineID || body.End != "" || body.EndedAt != 0 {
			return empty, hold("page_history")
		}
		if _, dup := oldPages[page.Page]; dup {
			return empty, hold("page_history")
		}
		oldPages[page.Page] = oldPage{page, r, body}
		for _, id := range body.Chunks {
			if _, ok := minSeq[id]; !ok {
				return empty, hold("page_history_unavailable")
			}
			memberSet[id] = true
		}
	}
	for i := int64(0); i < int64(len(oldPages)); i++ {
		if _, ok := oldPages[i]; !ok {
			return empty, hold("page_history")
		}
	}
	if len(groups) > 64 || len(memberSet)+len(groups) > 16*record.MaxSnapshotChunks {
		return empty, hold("plan_limit")
	}
	// A new chunk/page needs room in the plan even when the source is bounded.
	predictedPages := max(1, (len(memberSet)+len(groups)+record.MaxSnapshotChunks-1)/record.MaxSnapshotChunks)
	if len(groups)+predictedPages > 64 {
		return empty, hold("plan_limit")
	}
	if h == nil || !h.quiet(time.Now()) {
		return empty, hold("source_changed")
	}
	lease := p.keys
	defer lease.Clear()
	if !lease.valid || lease.keyID != c.CheckedAuthorKeyID {
		return empty, hold("key_material")
	}
	plan := store.CommitPlan{Next: store.CaptureNext{SettledThrough: q.Range.LastExclusive - 1, Reader: q.Reader, RulesetFingerprint: q.RulesetFingerprint, Range: q.Range}}
	newBytes := 0
	reuse := map[string]bool{}
	addNew := func(r store.SignedRecord) error {
		newBytes += len(r.HeaderJCS) + len(r.BodyJCS)
		if len(plan.NewRecords) >= 64 || newBytes > 16<<20 {
			return hold("plan_limit")
		}
		plan.NewRecords = append(plan.NewRecords, r)
		return nil
	}
	for _, group := range groups {
		sealed := make([]record.Event, len(group))
		deps := map[string]bool{}
		for i, d := range group {
			e := d.event
			if d.mint {
				e, err = record.ReviseEvent(e, d.parents)
				if err != nil {
					return empty, hold("sealing_failed")
				}
			} else {
				deps[d.source] = true
			}
			if e.Revision == "" || e.Salt == "" {
				return empty, hold("sealing_failed")
			}
			sealed[i] = e
		}
		id := ""
		for _, old := range chunks {
			if p.reusableHeader(old.record.Header, q) && reflect.DeepEqual(old.events, sealed) {
				id = old.id
				reuse[id] = true
				break
			}
		}
		if id == "" {
			links := record.Links{}
			for dep := range deps {
				if dep != "" {
					links.DerivedFrom = append(links.DerivedFrom, dep)
				}
			}
			sort.Strings(links.DerivedFrom)
			r, err := p.build(q, record.KindChunk, record.ChunkLID(q.Occurrence.SessionKey, p.config.MachineID, sealed[0].ID), &record.ChunkBody{Events: sealed}, links, lease)
			if err != nil {
				return empty, err
			}
			if err = addNew(r); err != nil {
				return empty, err
			}
			id = r.AdvisoryID
		}
		minSeq[id] = sealed[0].Seq
		memberSet[id] = true
		plan.Next.LastSourceRecordIDs = append(plan.Next.LastSourceRecordIDs, id)
	}
	members := make([]string, 0, len(memberSet))
	for id := range memberSet {
		members = append(members, id)
	}
	sort.Slice(members, func(i, j int) bool {
		if minSeq[members[i]] != minSeq[members[j]] {
			return minSeq[members[i]] < minSeq[members[j]]
		}
		return members[i] < members[j]
	})
	pageCount := (len(members) + record.MaxSnapshotChunks - 1) / record.MaxSnapshotChunks
	if pageCount == 0 || pageCount > 16 {
		return empty, hold("plan_limit")
	}
	for i := 0; i < pageCount; i++ {
		end := min(len(members), (i+1)*record.MaxSnapshotChunks)
		body := &record.SessionBody{NativeID: batch.nativeSession, NativeIDKind: record.NativeGlobal, Page: int64(i), Chunks: append([]string(nil), members[i*record.MaxSnapshotChunks:end]...), SettledThrough: q.Range.LastExclusive - 1, Reader: &record.SourceRef{Reader: q.Reader.Reader, ReaderVersion: q.Reader.ReaderVersion}}
		links := record.Links{}
		id := ""
		if old, ok := oldPages[int64(i)]; ok {
			bare := *old.b
			bare.Salt = ""
			if p.reusableHeader(old.r.Header, q) && reflect.DeepEqual(&bare, body) {
				id = old.ref.ID
				reuse[id] = true
			} else {
				links.Prev = old.ref.ID
				links.Supersedes = []string{old.ref.ID}
			}
		}
		if id == "" {
			r, err := p.build(q, record.KindSession, record.SessionLID(q.Occurrence.SessionKey, p.config.MachineID, int64(i)), body, links, lease)
			if err != nil {
				return empty, err
			}
			if err = addNew(r); err != nil {
				return empty, err
			}
			id = r.AdvisoryID
		}
		plan.Next.SessionPageIDs = append(plan.Next.SessionPageIDs, store.PageRef{Page: int64(i), ID: id})
	}
	for id := range reuse {
		plan.ReuseRecordIDs = append(plan.ReuseRecordIDs, id)
	}
	sort.Strings(plan.ReuseRecordIDs)
	if !h.quiet(time.Now()) {
		return empty, hold("source_changed")
	}
	return plan, nil
}

func (p *Pipeline) reusableHeader(h record.Header, q store.CaptureRequest) bool {
	return h.Pol == q.PolicyID && h.Prov == record.ProvTranscript && h.Author.MachineID == p.config.MachineID && h.Subj.SessionKey == q.Occurrence.SessionKey && h.Subj.Source == q.Occurrence.Source && h.Subj.Client != nil && h.Subj.Client.ID == q.Reader.Reader && h.Red.Profile == record.ProfileLocal && h.Red.Epoch == p.ruleset.Epoch && h.Red.Fingerprint == q.RulesetFingerprint && h.Trust.Coverage == "incomplete" && equalStrings(h.Trust.Taint, []string{"taint-unknown"})
}
func (p *Pipeline) build(q store.CaptureRequest, kind record.Kind, lid string, body any, links record.Links, lease PreloadedKeyMaterial) (store.SignedRecord, error) {
	defer lease.Clear()
	h := record.Header{Type: kind, LID: lid, Author: record.Author{MachineID: p.config.MachineID, KeyID: lease.keyID}, At: time.Now().UnixMilli(), Prov: record.ProvTranscript, Subj: record.Subject{SessionKey: q.Occurrence.SessionKey, Source: q.Occurrence.Source, Client: &record.ClientRef{ID: q.Reader.Reader, Surface: "cli"}}, Red: record.Redact{Profile: record.ProfileLocal, Epoch: p.ruleset.Epoch, Fingerprint: q.RulesetFingerprint}, Trust: record.Trust{Taint: []string{"taint-unknown"}, Coverage: "incomplete"}, Links: links}
	// PolicyID comes from the same acquired store writer as authority/progress.
	// The preparation snapshot alone cannot authorize a seal after a policy race.
	h.Pol = q.PolicyID
	r, err := record.Build(h, body)
	if err != nil {
		return store.SignedRecord{}, hold("record_invalid")
	}
	signature, err := sig.SignRecord(ed25519.PrivateKey(lease.private[:]), r.ID)
	if err != nil {
		return store.SignedRecord{}, hold("signing_failed")
	}
	return store.SignedRecord{HeaderJCS: r.HeaderJCS, BodyJCS: r.BodyJCS, Sigs: []record.Signature{signature}, AdvisoryID: r.ID}, nil
}
