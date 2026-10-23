package store

import (
	"github.com/Telara-Labs/telara-memory/contract/heads"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
	"github.com/Telara-Labs/telara-memory/contract/view"
)

type bindingChoice struct {
	value view.Binding
	id    string
}
type metadataGroups struct {
	tasks         map[[2]string][]view.Observed
	bindings      map[[2]string][]view.Observed
	taskStatus    map[[2]string]string
	bindingResult map[[2]string]bindingChoice
	head          map[string]bool
}

// These pure reducers inspect only owner, immutable headers/body and current
// Live/Admissible status. Taint does not enter their contracts. A rebuild or
// body removal invalidates the index; generation alone is not a cache key.
func (d *databaseState) metadataGroups() *metadataGroups {
	if d.groups != nil {
		return d.groups
	}
	g := &metadataGroups{tasks: map[[2]string][]view.Observed{}, bindings: map[[2]string][]view.Observed{}, taskStatus: map[[2]string]string{}, bindingResult: map[[2]string]bindingChoice{}}
	for _, x := range d.records {
		h := x.rec.Header
		o := view.Observed{Record: x.rec, Owner: x.owner, Live: available(x), Admissible: x.sigStatus == sig.StatusVerified && x.state != "ancestry-pending" && x.state != "lineage-hold"}
		if h.Subj.TaskID != "" {
			key := [2]string{x.owner, h.Subj.TaskID}
			g.tasks[key] = append(g.tasks[key], o)
		}
		if h.Type == record.KindBinding {
			key := [2]string{x.owner, h.LID}
			g.bindings[key] = append(g.bindings[key], o)
		}
	}
	d.groups = g
	return g
}
func (d *databaseState) taskStatus(owner, task string) string {
	g := d.metadataGroups()
	key := [2]string{owner, task}
	if v, ok := g.taskStatus[key]; ok {
		return v
	}
	v := view.TaskStatus(g.tasks[key], nil, owner, task)
	g.taskStatus[key] = v
	return v
}
func (d *databaseState) binding(ref, owner string) (view.Binding, string) {
	g := d.metadataGroups()
	key := [2]string{owner, record.BindingLID(ref)}
	if v, ok := g.bindingResult[key]; ok {
		return v.value, v.id
	}
	observed := g.bindings[key]
	b := view.ResolveBinding(observed, nil, ref, owner)
	out := bindingChoice{value: b}
	if b.Target != nil {
		var versions []heads.Version
		byID := map[string]*record.BindingBody{}
		for _, o := range observed {
			if body, ok := o.Record.Body.(*record.BindingBody); ok && body.CallRef == ref {
				versions = append(versions, heads.FromHeader(o.Record.ID, &o.Record.Header, owner, o.Live && o.Admissible))
				byID[o.Record.ID] = body
			}
		}
		for _, h := range heads.HeadsForOwner(versions, nil, key[1], record.KindBinding, owner) {
			body := byID[h.ID]
			if body.Target != nil && body.Status == "bound" && body.Target.SessionKey == b.Target.SessionKey && body.Confidence == b.Confidence {
				out.id = h.ID
				break
			}
		}
		if out.id == "" {
			out.value = view.Binding{Status: "unbound"}
		}
	}
	g.bindingResult[key] = out
	return out.value, out.id
}
func (d *databaseState) groupedHeads() map[string]bool {
	g := d.metadataGroups()
	if g.head != nil {
		return g.head
	}
	out := map[string]bool{}
	groups := map[[3]string][]heads.Version{}
	for _, x := range d.records {
		h := x.rec.Header
		if h.Type.IsControl() {
			continue
		}
		key := [3]string{x.owner, string(h.Type), h.LID}
		groups[key] = append(groups[key], heads.FromHeader(x.rec.ID, &h, x.owner, available(x)))
		if available(x) && record.ReducerOf(h.Type, h.Prov) == record.Set {
			out[x.rec.ID] = true
		}
	}
	// Heads filters owner, kind and LID itself. All headers of that exact group,
	// including unavailable superseders, remain present; foreign groups cannot
	// shadow a local header, and an unknown target is ignored by the pure reducer.
	for key, versions := range groups {
		for _, h := range heads.HeadsForOwner(versions, nil, key[2], record.Kind(key[1]), key[0]) {
			out[h.ID] = true
		}
	}
	g.head = out
	return out
}
