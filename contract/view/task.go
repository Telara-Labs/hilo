package view

import (
	"github.com/Telara-Labs/telara-memory/contract/heads"
	"github.com/Telara-Labs/telara-memory/contract/record"
)

// TaskStatus only reduces records of this exact verified owner and task.
func TaskStatus(all []Observed, index []heads.Pair, owner, taskID string) string {
	var vs []heads.Version
	byID := map[string]*record.Record{}
	var taskLID, conclusionLID string
	for _, o := range all {
		if o.Record == nil {
			continue
		}
		r := o.Record
		if o.Owner != owner || r.Header.Subj.TaskID != taskID {
			continue
		}
		vs = append(vs, heads.FromHeader(r.ID, &r.Header, o.Owner, o.Live && o.Admissible))
		byID[r.ID] = r
		if r.Header.Type == record.KindTask {
			taskLID = r.Header.LID
		}
		if r.Header.Type == record.KindConclusion && (r.Header.Prov == record.ProvMCPExplicit || r.Header.Prov == record.ProvGateway) {
			conclusionLID = r.Header.LID
		}
	}
	if len(heads.HeadsForOwner(vs, index, conclusionLID, record.KindConclusion, owner)) > 0 {
		return "completed"
	}
	var newest heads.Version
	for _, v := range vs {
		if v.Live && (v.Type == record.KindCheckpoint || v.Type == record.KindPause) && (newest.ID == "" || heads.Less(newest, v)) {
			newest = v
		}
	}
	if newest.Type == record.KindPause {
		return "paused"
	}
	if h, ok := heads.Head(vs, index, taskLID, record.KindTask); ok {
		if b, ok := byID[h.ID].Body.(*record.TaskBody); ok {
			return b.Status
		}
	}
	return "absent"
}

type Binding struct {
	Status, Confidence string
	Target             *record.BindTarget
}

func ResolveBinding(all []Observed, index []heads.Pair, callRef, owner string) Binding {
	var vs []heads.Version
	bs := map[string]*record.BindingBody{}
	lid := record.BindingLID(callRef)
	for _, o := range all {
		if o.Record == nil || o.Owner != owner || o.Record.Header.Type != record.KindBinding || o.Record.Header.LID != lid {
			continue
		}
		b, ok := o.Record.Body.(*record.BindingBody)
		if !ok {
			continue
		}
		vs = append(vs, heads.FromHeader(o.Record.ID, &o.Record.Header, o.Owner, o.Live && o.Admissible))
		bs[o.Record.ID] = b
	}
	result := Binding{Status: "unbound"}
	rank := 0
	for _, h := range heads.HeadsForOwner(vs, index, lid, record.KindBinding, owner) {
		b := bs[h.ID]
		if b.Status != "bound" {
			continue
		}
		r := record.ConfidenceRank(b.Confidence)
		if r > rank {
			rank = r
			result = Binding{Status: "bound", Confidence: b.Confidence, Target: b.Target}
		} else if r == rank && result.Target != nil && b.Target != nil && result.Target.SessionKey != b.Target.SessionKey {
			result.Status = "ambiguous"
			result.Target = nil
		}
	}
	return result
}

// MayCorrectBinding refuses a lower-confidence attempt to supersede a stronger binding.
func MayCorrectBinding(current, newConfidence string) bool {
	return record.ConfidenceRank(newConfidence) > 0 && record.ConfidenceRank(newConfidence) >= record.ConfidenceRank(current)
}
