package record

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/Telara-Labs/telara-memory/contract/jcs"
	"sort"
	"strings"
)

var ReceiptTools = []string{"telara_task_list", "telara_task_create", "telara_task_resume", "telara_task_checkpoint", "telara_task_pause", "telara_task_complete", "telara_knowledge_search", "telara_get_context"}

func ValidReceiptTool(tool string) bool {
	// Do not trust a mutable exported inventory for admission.
	switch tool {
	case "telara_task_list", "telara_task_create", "telara_task_resume", "telara_task_checkpoint", "telara_task_pause", "telara_task_complete", "telara_knowledge_search", "telara_get_context":
		return true
	}
	return false
}
func ValidScopeID(scope, machine string) bool {
	parts := strings.Split(scope, ":")
	return len(parts) == 3 && parts[0] == "sc1" && IsUUIDv4(parts[1]) && parts[1] == machine && IsKeyID(parts[2])
}

func keyedCommitment(salt, domain string, values ...any) (string, error) {
	key, err := base64.RawURLEncoding.Strict().DecodeString(salt)
	if err != nil || !validEventSalt(salt) {
		return "", fmt.Errorf("commitment key unavailable")
	}
	defer clear(key)
	all := append([]any{domain}, values...)
	// Commitment preimages are JSON values, not record members. Null and
	// fractional numbers remain valid here; wire bodies keep the record gate.
	raw, err := jcs.Marshal(all)
	if err != nil {
		return "", err
	}
	defer clear(raw)
	mac := hmac.New(sha256.New, key)
	mac.Write(raw)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// CallCommitment verifies/recomputes only a live body's declared comparator.
// The adapter must check liveness, complete provenance and key eligibility first.
// It is not an authoring override or a comparator against retained erased facts.
func CallCommitment(salt, part, tool string, redacted json.RawMessage) (string, error) {
	if !ValidReceiptTool(tool) || (part != "args" && part != "result") || len(redacted) == 0 {
		return "", fmt.Errorf("invalid call commitment input")
	}
	c, err := jcs.Canonicalize(redacted)
	if err != nil {
		return "", err
	}
	defer clear(c)
	return keyedCommitment(salt, "mnc3-call-"+part, tool, json.RawMessage(c))
}
func EventTextCommitment(salt, fullRedacted string) (string, error) {
	return keyedCommitment(salt, "mnc3-event-text", fullRedacted)
}

// ValidateCommitmentDependencies validates the complete signed wire set. Known
// roots must come from verified mutation/result provenance, never caller claims.
// Unknown ancestry is handled separately and may never default to an empty set.
func ValidateCommitmentDependencies(r *Record, known []string) error {
	if r == nil {
		return rej(CodeCommitmentDependencies, "call required")
	}
	parsed, err := Parse(r.HeaderJCS, r.BodyJCS, r.ID)
	if err != nil {
		return rej(CodeCommitmentDependencies, "invalid canonical call")
	}
	return validateCommitmentDependencies(parsed, known)
}
func validateCommitmentDependencies(r *Record, known []string) error {
	if r == nil || r.Header.Type != KindCall {
		return rej(CodeCommitmentDependencies, "call required")
	}
	b, ok := r.Body.(*CallBody)
	if !ok {
		return rej(CodeCommitmentDependencies, "full call body required")
	}
	if b.CommitmentDeps == nil || !sort.StringsAreSorted(b.CommitmentDeps) || !uniqueHex64(b.CommitmentDeps) || len(b.CommitmentDeps) > 8192 || !sort.StringsAreSorted(r.Header.Links.DerivedFrom) || len(b.CommitmentDeps) != len(r.Header.Links.DerivedFrom) {
		return rej(CodeCommitmentDependencies, "invalid dependency set")
	}
	for i, id := range b.CommitmentDeps {
		if id == r.ID || id != r.Header.Links.DerivedFrom[i] {
			return rej(CodeCommitmentDependencies, "dependency mismatch")
		}
	}
	for _, id := range known {
		if !containsString(b.CommitmentDeps, id) {
			return rej(CodeCommitmentDependencies, "omitted verified dependency")
		}
	}
	return nil
}
