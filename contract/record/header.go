// Package record is the record envelope of the memory node contract: the
// signed header, the kind union and its bodies, content ids, salted body
// digests, per-kind LID rules, size limits and admission checks.
package record

import (
	"crypto/sha256"
	"encoding/hex"
)

// Version is the contract major version carried in Header.V.
const Version = 2

// ContractVersion is the full contract version this module implements.
const ContractVersion = "mnc/2.0"

// Size limits (R1.6).
const (
	MaxHeaderBytes    = 16 << 10 // decoded header_jcs
	MaxBodyBytes      = 1 << 20  // decoded (uncompressed) body_jcs, every kind
	MaxChunkEvents    = 256
	MaxSnapshotChunks = 8192
	MaxRetractionIDs  = 4096
	MaxErasureEntries = 8192
	MaxMetaPointers   = 64
	MaxTitleRunes     = 120
	MaxRequestBytes   = 1000
	MaxTextBytes      = 16 << 10
)

// Header is hashed and signed. It carries identity, routing and filter
// metadata only, never free text written by a user, a model or a tool. It
// survives erasure. Empty optional fields are omitted, never null.
type Header struct {
	V      int      `json:"v"`
	Type   Kind     `json:"type"`
	LID    string   `json:"lid"`
	Author Author   `json:"author"`
	At     int64    `json:"at"` // authoring time, unix ms; tie-break only
	Prov   Prov     `json:"prov"`
	Subj   Subject  `json:"subj"`
	Red    Redact   `json:"red"`
	Trust  Trust    `json:"trust"`
	Links  Links    `json:"links,omitzero"`
	Body   *BodyRef `json:"body,omitempty"`
	Op     string   `json:"op,omitempty"`
	Pol    string   `json:"pol,omitempty"` // id of the tenant policy in force at seal, §9.4
}

// Author is who signed. KeyID = hex(sha256(pub))[:32].
type Author struct {
	MachineID string `json:"machine_id,omitempty"`
	KeyID     string `json:"key_id"`
}

// Subject is what the record is about.
type Subject struct {
	SessionKey string     `json:"session_key,omitempty"`
	TaskID     string     `json:"task_id,omitempty"`
	RepoID     string     `json:"repo_id,omitempty"`
	Client     *ClientRef `json:"client,omitempty"`
	Source     string     `json:"source,omitempty"` // source key, §1.4
}

// IsZero lets encoding/json omit an empty subject.
func (s Subject) IsZero() bool {
	return s.SessionKey == "" && s.TaskID == "" && s.RepoID == "" && s.Client == nil && s.Source == ""
}

// ClientRef names the capturing client.
type ClientRef struct {
	ID      string `json:"id"`
	Version string `json:"version,omitempty"`
	Surface string `json:"surface,omitempty"` // cli | ide | desktop | cloud | connector
}

// Links are the record's references to other records.
type Links struct {
	Supersedes  []string `json:"supersedes,omitempty"`   // same-LID ids this replaces
	DerivedFrom []string `json:"derived_from,omitempty"` // ids whose content this copies
	Origin      string   `json:"origin,omitempty"`       // export source id, immutable lineage
	Prev        string   `json:"prev,omitempty"`         // previous snapshot by this author
}

// IsZero lets encoding/json omit empty links.
func (l Links) IsZero() bool {
	return len(l.Supersedes) == 0 && len(l.DerivedFrom) == 0 && l.Origin == "" && l.Prev == ""
}

// BodyRef binds the body into the id: hex(sha256(body_jcs)) and len(body_jcs).
type BodyRef struct {
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
}

// Redact is the header redaction state (§6.3).
type Redact struct {
	Profile     string `json:"profile"`
	Epoch       int    `json:"epoch"`
	Fingerprint string `json:"fingerprint,omitempty"` // Ruleset.Fingerprint, §6.2
	Findings    int    `json:"findings"`              // total count only
}

// Trust is the author's taint and coverage claim (§10.1).
type Trust struct {
	Taint    []string `json:"taint,omitempty"`
	Coverage string   `json:"coverage,omitempty"`
	Flags    []string `json:"flags,omitempty"`
}

// IsZero lets encoding/json omit an empty trust claim.
func (t Trust) IsZero() bool { return len(t.Taint) == 0 && t.Coverage == "" && len(t.Flags) == 0 }

// Signature is one signature over a record, bundle or receipt (§4.2).
type Signature struct {
	Alg   string `json:"alg"`    // "ed25519"
	KeyID string `json:"key_id"` // hex(sha256(raw32 pub))[:32]
	Ctx   string `json:"ctx"`    // mnc/v1/record | mnc/v1/bundle | mnc/v1/receipt
	Value string `json:"value"`  // base64url, 64 bytes, no padding
}

// Receipt is a hosted acceptance fact, signed by the tenant service key.
type Receipt struct {
	ID         string     `json:"id"`
	Tenant     string     `json:"tenant"`
	DeviceID   string     `json:"device_id"`
	AcceptedAt int64      `json:"accepted_at"`
	HSeq       int64      `json:"hseq"`
	Policy     string     `json:"policy,omitempty"` // id of the policy hosted enforced
	Sig        *Signature `json:"sig,omitempty"`
}

// EnvelopeBody is the transported body. Codec "zstd" is a transport encoding
// outside the digest; this module does not decompress (see OPEN-QUESTIONS).
type EnvelopeBody struct {
	Codec string `json:"codec"`
	Bytes string `json:"bytes"` // base64url
}

// Envelope is what crosses the wire and sits in bundles (§8.1). ID is
// advisory and always recomputed.
type Envelope struct {
	V       int            `json:"v"`
	ID      string         `json:"id"`
	Header  string         `json:"header"` // base64url header_jcs
	Sigs    []Signature    `json:"sigs"`
	Body    *EnvelopeBody  `json:"body,omitempty"`
	Receipt *Receipt       `json:"receipt,omitempty"`
	Grant   *DeliveryGrant `json:"grant,omitempty"`
}

// ContentID returns lowercase hex(sha256(header_jcs)) (R1.2).
func ContentID(headerJCS []byte) string {
	sum := sha256.Sum256(headerJCS)
	return hex.EncodeToString(sum[:])
}

// BodyDigest returns hex(sha256(body_jcs)) over the uncompressed canonical body (R1.3).
func BodyDigest(bodyJCS []byte) string {
	sum := sha256.Sum256(bodyJCS)
	return hex.EncodeToString(sum[:])
}

// GrantRef is authenticated tenant provenance inherited by data and semantic output.
type GrantRef struct {
	Tenant     string `json:"tenant"`
	Generation int64  `json:"generation"`
}

// DeliveryGrant is a service-signed delivery fact, separate from acceptance.
type DeliveryGrant struct {
	RecordID         string     `json:"record_id"`
	Tenant           string     `json:"tenant"`
	Generation       int64      `json:"generation"`
	Policy           string     `json:"policy"`
	RecipientGenesis string     `json:"recipient_genesis"`
	Sig              *Signature `json:"sig,omitempty"`
}
