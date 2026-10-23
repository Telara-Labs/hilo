package view

import (
	"github.com/Telara-Labs/telara-memory/contract/record"
	"sort"
)

type EventTaint struct {
	Seq  int64
	Tags []string
}
type EffectiveTrust struct {
	Observed  []string
	Uncertain bool
	Coverage  string
}

func (t EffectiveTrust) Effective() []string {
	out := append([]string(nil), t.Observed...)
	if t.Uncertain {
		out = append(out, "taint-unknown")
	}
	sort.Strings(out)
	return out
}

type TrustInput struct {
	Header                          record.Trust
	Kind                            record.Kind
	Provenance                      record.Prov
	Verified, AncestryResolved      bool
	Session                         *Session
	Boundary                        int64
	EventSequences                  []int64
	BindingConfidence               string
	Inputs                          []EffectiveTrust
	CopiedInputs                    int
	Events                          []EventTaint
	OriginRequired, OriginAvailable bool
}

// Trust separates monotone observed taint from recomputed uncertainty.
func Trust(in TrustInput) EffectiveTrust {
	tags := map[string]bool{}
	add := func(xs []string) {
		for _, t := range xs {
			if t != "taint-unknown" {
				tags[t] = true
			}
		}
	}
	add(in.Header.Taint)
	complete := in.Verified && in.AncestryResolved
	derived := in.Provenance == record.ProvDerived && (in.Kind == record.KindDigest || in.Kind == record.KindRollup || in.OriginRequired)
	if derived {
		complete = complete && in.CopiedInputs > 0 && len(in.Inputs) == in.CopiedInputs
		for _, d := range in.Inputs {
			complete = complete && d.Coverage == "complete" && !d.Uncertain
		}
	} else {
		switch in.Kind {
		case record.KindTask, record.KindCheckpoint, record.KindPause, record.KindCall, record.KindConclusion:
			complete = complete && record.ConfidenceRank(in.BindingConfidence) >= record.ConfidenceRank("transcript-echo") && in.Session.CoverageAt(in.Boundary)
		case record.KindSession:
			complete = complete && in.Session.CoverageAt(in.Boundary)
		case record.KindChunk:
			complete = complete && len(in.EventSequences) > 0
			for _, seq := range in.EventSequences {
				complete = complete && in.Session.CoverageAt(seq)
			}
		default:
			complete = false
		}
	}
	if in.OriginRequired && !in.OriginAvailable {
		complete = false
	}
	for _, d := range in.Inputs {
		add(d.Observed)
	}
	events := append([]EventTaint(nil), in.Events...)
	if in.Session != nil {
		events = append(events, in.Session.TaintEvents...)
	}
	for _, e := range events {
		if e.Seq <= in.Boundary {
			add(e.Tags)
		}
	}
	out := EffectiveTrust{Uncertain: !complete, Coverage: "incomplete"}
	if complete {
		out.Coverage = "complete"
	}
	for t := range tags {
		out.Observed = append(out.Observed, t)
	}
	sort.Strings(out.Observed)
	return out
}

type ReadContext struct {
	Channel                                                                                                      string
	Kind                                                                                                         record.Kind
	Verified, Quarantined, Held, Invalidated, SameRepo, OwnGenesis, HookEnabled, GrantAllowed, InstructionShaped bool
	Trust                                                                                                        EffectiveTrust
}

func Eligible(c ReadContext) bool {
	if !c.GrantAllowed || c.Quarantined || c.Held || c.Invalidated {
		return false
	}
	if c.Channel == "S" {
		return true
	}
	if !c.Verified || c.Trust.Coverage != "complete" || c.Trust.Uncertain {
		return false
	}
	switch c.Channel {
	case "P", "E":
		return true
	case "H":
		return c.HookEnabled && c.OwnGenesis && c.SameRepo && !c.InstructionShaped && len(c.Trust.Observed) == 0 && (c.Kind == record.KindConclusion || c.Kind == record.KindCheckpoint)
	}
	return false
}
