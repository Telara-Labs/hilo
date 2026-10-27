// Package heads is deterministic head selection over a record set.
//
// Heads depend only on the set of admitted headers. Arrival order, receive
// time, hosted sequence numbers and bundle order are not inputs, so every
// replica holding the same set computes the same heads.
package heads

import (
	"sort"

	"github.com/Telara-Labs/hilo/contract/record"
)

// Version is what head selection reads from one admitted header.
type Version struct {
	ID         string
	LID        string
	Type       record.Kind
	Owner      string // owner of the verified signer; supersedes across owners is ignored
	At         int64
	Profile    string // red.profile
	Supersedes []string
	// Live is false once the record is invalidated (erased, retracted,
	// withdrawn). An invalidated header still supersedes what it named.
	Live bool
}

// FromHeader builds a Version from an admitted record and its signer's owner.
func FromHeader(id string, h *record.Header, owner string, live bool) Version {
	return Version{ID: id, LID: h.LID, Type: h.Type, Owner: owner, At: h.At, Profile: h.Red.Profile,
		Supersedes: append([]string(nil), h.Links.Supersedes...), Live: live}
}

// Pair is one entry of the persistent supersession index: From superseded
// To. The index survives body and header purge, so a superseder whose header
// is gone still keeps its target superseded.
type Pair struct {
	From, To, Owner, LID string
	Type                 record.Kind
}

// Less orders by key(r) = (At, ID), compared as (int64, bytewise string).
func Less(a, b Version) bool {
	if a.At != b.At {
		return a.At < b.At
	}
	return a.ID < b.ID
}

// Heads returns the heads of logical id lid and kind k, sorted by key
// descending. all holds every admitted header known for any LID; index holds
// supersession pairs whose superseding header may no longer be present.
//
//	Versions(L)   = live records with lid L and type k
//	shadowed      : if any version has profile "local", versions with any
//	                other profile are dropped on this node
//	Superseded(L) = ids named in supersedes by any admitted header of L
//	                (live or invalidated) with the same type and owner, plus
//	                index pairs whose target is in L
//	Heads(L)      = Versions(L) \ Superseded(L)
func Heads(all []Version, index []Pair, lid string, k record.Kind) []Version {
	inL := map[string]Version{}
	for _, v := range all {
		if v.LID == lid && v.Type == k {
			inL[v.ID] = v
		}
	}
	superseded := map[string]bool{}
	for _, v := range inL {
		for _, target := range v.Supersedes {
			t, ok := inL[target]
			// A different LID or type is ignored; so is another owner
			if ok && t.Owner == v.Owner && target != v.ID {
				superseded[target] = true
			}
		}
	}
	for _, p := range index {
		from, okFrom := inL[p.From]
		to, okTo := inL[p.To]
		if okTo && p.Owner == to.Owner && p.LID == to.LID && p.Type == to.Type && (!okFrom || from.Owner == to.Owner) && p.From != p.To {
			superseded[p.To] = true
		}
	}
	var versions []Version
	local := false
	for _, v := range inL {
		if v.Live {
			versions = append(versions, v)
			if v.Profile == record.ProfileLocal {
				local = true
			}
		}
	}
	var out []Version
	for _, v := range versions {
		if local && v.Profile != record.ProfileLocal {
			continue
		}
		if !superseded[v.ID] {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return Less(out[j], out[i]) })
	return out
}

// Head returns the single head (HeadSingle): the maximum key among Heads.
func Head(all []Version, index []Pair, lid string, k record.Kind) (Version, bool) {
	h := Heads(all, index, lid, k)
	if len(h) == 0 {
		return Version{}, false
	}
	return h[0], true
}

// Conflict reports whether a HeadMulti LID currently has concurrent heads.
func Conflict(all []Version, index []Pair, lid string, k record.Kind) bool {
	return len(Heads(all, index, lid, k)) > 1
}

// HeadsForOwner is the task/graph lookup entry point. Never join on a bare UUID.
func HeadsForOwner(all []Version, index []Pair, lid string, k record.Kind, owner string) []Version {
	var scoped []Version
	for _, v := range all {
		if v.Owner == owner {
			scoped = append(scoped, v)
		}
	}
	var pairs []Pair
	for _, p := range index {
		if p.Owner == owner {
			pairs = append(pairs, p)
		}
	}
	return Heads(scoped, pairs, lid, k)
}
