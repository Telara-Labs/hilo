package store

import (
	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/view"
	"sync/atomic"
)

const (
	maxCaptureNewRecords   = 64
	maxCaptureReuseRecords = 80
	maxCaptureRecordRefs   = maxCaptureNewRecords + maxCaptureReuseRecords
)

// Capture APIs are for a trusted in-process producer, never native input or RPC.
type CaptureIdentity struct{ OwnerGenesis, MachineID, StoreInstanceID string }
type CaptureInspection struct {
	Progress    CaptureProgress
	Suppression Suppression
}
type CaptureRange struct{ First, LastExclusive int64 }
type RecordRef struct {
	ID       string
	Sequence int64
}
type PageRef struct {
	Page int64
	ID   string
}
type CaptureProgress struct {
	Version, SettledThrough int64
	LastSourceRecords       []RecordRef
	SessionPages            []PageRef
	Reader                  record.SourceRef
	RulesetFingerprint      string
	Range                   CaptureRange
}
type CaptureRequest struct {
	RepositoryBinding    string          `json:"repository_binding,omitempty"`
	RepositoryGeneration int64           `json:"repository_generation,omitempty"`
	Repository           *record.RepoRef `json:"repository,omitempty"`
	PolicyID             string          // supplied only by the trusted producer from CaptureContext
	Occurrence           SourceOccurrence
	AuthorKeyID          string
	ExpectedVersion      int64
	Reader               record.SourceRef
	RulesetFingerprint   string
	EventIDs             []string
	Range                CaptureRange
}
type CaptureNext struct {
	SettledThrough      int64
	LastSourceRecordIDs []string
	SessionPageIDs      []PageRef
	Reader              record.SourceRef
	RulesetFingerprint  string
	Range               CaptureRange
}
type CommitPlan struct {
	NewRecords     []SignedRecord
	ReuseRecordIDs []string
	Next           CaptureNext
}
type CaptureReceipt struct {
	Status              string
	ActualRecordRefs    []RecordRef
	CurrentAvailability map[string]string
	ResultingProgress   CaptureProgress
	TransitionID        string
}
type CaptureContext struct {
	RepositoryBinding                                       string
	RepositoryGeneration                                    int64
	Repository                                              record.RepoRef
	PolicyID                                                string
	OwnerGenesis, MachineID, CheckedAuthorKeyID             string
	AuthorityGeneration, ErasureGeneration, ProgressVersion int64
}
type CaptureRecord struct {
	RecordRef
	Availability string
	SignedRecord
}
type CapturePage struct {
	PageRef
	Prev, Availability string
	SignedRecord
}
type CaptureEventHistory struct {
	ID                                                         string
	KnownPresence, CompleteFrontier, Banned, Pending, Conflict bool
	Copies                                                     []view.EventVersion
	Facts                                                      view.EventFacts
	MaximalRevisionIDs                                         []string
}

// The view expires before persistence. Every returned value is a detached copy.
type CaptureTxn struct {
	valid    atomic.Bool
	context  CaptureContext
	progress CaptureProgress
	prior    []CaptureRecord
	pages    []CapturePage
	events   map[string]CaptureEventHistory
}
