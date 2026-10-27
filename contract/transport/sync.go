// Package transport contains pure wire and admission gates. The node/hosted
// adapters own authenticated transport, compression, durable transactions and I/O.
package transport

import (
	"errors"
	"github.com/Telara-Labs/hilo/contract/record"
	"sort"
)

type Hello struct {
	DeviceID      string `json:"device_id"`
	Contract      string `json:"contract"`
	CtlCursor     int64  `json:"ctl_cursor"`
	DataCursor    int64  `json:"data_cursor"`
	KeysetVersion int64  `json:"keyset_version"`
	OutboxDepth   int64  `json:"outbox_depth"`
}
type HelloReply struct {
	ContractMin   string `json:"contract_min"`
	CtlHead       int64  `json:"ctl_head"`
	DataHead      int64  `json:"data_head"`
	KeysetVersion int64  `json:"keyset_version"`
	PolicySeq     int64  `json:"policy_seq"`
	ServerTime    int64  `json:"server_time"`
}
type Ack struct {
	CtlEnforcedThrough int64 `json:"ctl_enforced_through"`
	DataAppliedThrough int64 `json:"data_applied_through"`
}
type LogItem struct {
	DecodedBody []byte          `json:"-"` // bounded adapter-decompressed exact body bytes
	HSeq        int64           `json:"hseq"`
	Class       string          `json:"class"`
	Envelope    record.Envelope `json:"envelope"`
	Own         bool            `json:"-"`
}
type Page struct {
	Items          []LogItem `json:"items"`
	NextAfter      int64     `json:"next_after"`
	ScannedThrough int64     `json:"scanned_through"`
	More           bool      `json:"more"`
}

// ScanPage uses a fixed class snapshot. Own exclusions still advance its watermark.
func ScanPage(log []LogItem, class string, after, through int64, limit int, excludeOwn bool) (Page, error) {
	p := Page{Items: []LogItem{}, NextAfter: after, ScannedThrough: after}
	if (class != "control" && class != "data") || after < 0 || through < after || limit < 1 || class == "control" && excludeOwn {
		return p, errors.New("invalid class cursor or snapshot")
	}
	xs := append([]LogItem(nil), log...)
	sort.Slice(xs, func(i, j int) bool { return xs[i].HSeq < xs[j].HSeq })
	last := int64(0)
	for _, x := range xs {
		if x.HSeq <= last {
			return p, errors.New("log sequence not unique and positive")
		}
		last = x.HSeq
		if x.Class != "control" && x.Class != "data" {
			return p, errors.New("unknown log class")
		}
		if x.Class != class || x.HSeq <= after || x.HSeq > through {
			continue
		}
		if !excludeOwn || !x.Own {
			if len(p.Items) == limit {
				p.More = true
				break
			}
			p.Items = append(p.Items, x)
		}
		p.ScannedThrough = x.HSeq
	}
	if !p.More {
		p.ScannedThrough = through
	}
	p.NextAfter = p.ScannedThrough
	return p, nil
}

// ApplyPage must run with cursor persistence in the adapter's one page transaction.
// apply retains unknown data in quarantine, and returns false for unenforceable controls.
func ApplyPage(p Page, class string, cursor, through int64, apply func(LogItem) bool) (int64, bool, error) {
	if class != "control" && class != "data" || p.NextAfter != p.ScannedThrough || p.NextAfter < cursor || p.NextAfter > through || p.More && p.NextAfter == through {
		return cursor, false, errors.New("invalid page watermark")
	}
	last := cursor
	for _, x := range p.Items {
		if x.Class != class || x.HSeq <= last || x.HSeq > p.ScannedThrough {
			return cursor, false, errors.New("invalid page order or class")
		}
		last = x.HSeq
	}
	next := cursor
	for _, x := range p.Items {
		if !apply(x) && class == "control" {
			return next, true, nil
		}
		next = x.HSeq
	}
	return p.NextAfter, false, nil
}

type PushResult struct {
	ID      string          `json:"id"`
	Status  string          `json:"status"`
	HSeq    int64           `json:"hseq,omitempty"`
	Code    string          `json:"code,omitempty"`
	Receipt *record.Receipt `json:"receipt,omitempty"`
}

// CheckPushResult is structural only; the adapter MUST cryptographically verify
// the stored receipt before atomically marking its outbox row complete.
func CheckPushResult(p PushResult) error {
	if !record.IsHex64(p.ID) {
		return errors.New("invalid push id")
	}
	if p.Status == "accepted" || p.Status == "accepted-duplicate" {
		if p.Receipt == nil || p.Receipt.ID != p.ID || p.HSeq <= 0 || p.Receipt.HSeq != p.HSeq {
			return errors.New("acceptance requires matching stored receipt")
		}
	}
	return nil
}

type Authority struct {
	RuleID      string
	RuleVersion int64
	ExplicitOp  string
	Profile     string
}
type SendState struct {
	Live, AncestryResolved, PolicyAllowed, RuleMatches bool
	Grants                                             []record.GrantRef
	Kind                                               record.Kind
	Profile, RuleID                                    string
	RuleVersion                                        int64
}

// MaySend checks disclosure on every attempt, including explicit authority.
func MaySend(a Authority, s SendState) bool {
	if !s.Live || !s.AncestryResolved || !s.PolicyAllowed || len(s.Grants) > 0 || a.Profile != s.Profile || !(s.Kind.IsControl() && s.Profile == record.ProfileLocal || (s.Kind == record.KindSession || s.Kind == record.KindTask) && s.Profile == record.ProfilePushMetadata) {
		return false
	}
	if a.ExplicitOp != "" {
		return a.RuleID == "" && record.IsHex64(a.ExplicitOp)
	}
	return a.RuleID != "" && a.RuleID == s.RuleID && a.RuleVersion > 0 && a.RuleVersion == s.RuleVersion && s.RuleMatches
}
