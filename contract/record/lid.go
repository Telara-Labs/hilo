package record

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/Telara-Labs/telara-memory/contract/jcs"
)

// LID constructors. Each returns the 64-hex logical id.

// SessionLID is H("session", session_key, machine_id, page).
func SessionLID(sessionKey, machineID string, page int64) string {
	return H("session", sessionKey, machineID, pageString(page))
}

// ChunkLID is H("chunk", session_key, machine_id, first_event_id).
func ChunkLID(sessionKey, machineID, firstEventID string) string {
	return H("chunk", sessionKey, machineID, firstEventID)
}

// ExplicitConclusionLID is H("conclusion", "task", owner, task_id).
func ExplicitConclusionLID(owner, taskID string) string {
	return H("conclusion", "task", owner, taskID)
}

// RequestConclusionLID is H("conclusion", "request", session_key, request_key).
func RequestConclusionLID(sessionKey, requestKey string) string {
	return H("conclusion", "request", sessionKey, requestKey)
}

// TaskLID is H("task", owner, task_id).
func TaskLID(owner, taskID string) string { return H("task", owner, taskID) }

// CheckpointLID is H("checkpoint", owner, task_id, machine_id, op).
func CheckpointLID(owner, taskID, machineID, op string) string {
	return H("checkpoint", owner, taskID, machineID, op)
}

// PauseLID is H("pause", owner, task_id, machine_id, op).
func PauseLID(owner, taskID, machineID, op string) string {
	return H("pause", owner, taskID, machineID, op)
}

// CallLID is H("call", call_ref).
func CallLID(callRef string) string { return H("call", callRef) }

// BindingLID is H("binding", call_ref).
func BindingLID(callRef string) string { return H("binding", callRef) }

// DigestLID is H("digest", session_key, machine_id).
func DigestLID(sessionKey, machineID string) string { return H("digest", sessionKey, machineID) }

// RollupLID is H("rollup", owner, task_id, machine_id).
func RollupLID(owner, taskID, machineID string) string { return H("rollup", owner, taskID, machineID) }

// Owner returns the owner namespace of a verified signer: the genesis
// key id for a device key, "tenant:<id>" for a tenant service key. Policy
// keys own no task state and return "". It is derived from the keyring,
// never from a header field.
func Owner(role Role, genesisKeyID, tenant string) string {
	switch role {
	case RoleDevice:
		if IsKeyID(genesisKeyID) {
			return genesisKeyID
		}
	case RoleService:
		if tenant != "" {
			return "tenant:" + tenant
		}
	}
	return ""
}

// OwnerScoped reports whether a kind's LID includes the owner, so that only
// a verifier that knows the signer can recompute it.
func OwnerScoped(h *Header) bool {
	switch h.Type {
	case KindTask, KindCheckpoint, KindPause, KindRollup:
		return true
	case KindConclusion:
		return h.Prov == ProvMCPExplicit || h.Prov == ProvGateway
	}
	return false
}

// ControlLID is H(kind, author.key_id, nonce128) for retraction, erasure and
// withdrawal. nonce128 is 16 random bytes rendered as 32 lowercase hex.
func ControlLID(k Kind, authorKeyID, nonce128 string) (string, error) {
	if !k.IsControl() || k == KindKeyOp || k == KindPolicy {
		return "", fmt.Errorf("control lid: %q is not retraction, erasure or withdrawal", k)
	}
	if !IsKeyID(nonce128) {
		return "", fmt.Errorf("control lid: nonce must be 128 bits as 32 lowercase hex")
	}
	return HE(string(k), authorKeyID, nonce128)
}

// KeyLID is H("key", subject_key_id).
func KeyLID(subjectKeyID string) string { return H("key", subjectKeyID) }

// PolicyLID is H("policy", tenant_id).
func PolicyLID(tenantID string) string { return H("policy", tenantID) }

// ExpectedLID recomputes the LID of a record from its header, its decoded
// body when needed, and the owner of its verified signer. Pass owner "" when
// the signer is not yet known; owner-scoped kinds then report ok == false.
// ok is also false for control records (the nonce is not carried), export
// variants of sessions (the page is not in the meta body), records whose needed body is absent.
func ExpectedLID(h *Header, body any, owner string) (lid string, ok bool) {
	if OwnerScoped(h) && owner == "" {
		return "", false
	}
	m := h.Author.MachineID
	switch h.Type {
	case KindSession:
		if b, isS := body.(*SessionBody); isS {
			return SessionLID(h.Subj.SessionKey, m, b.Page), true
		}
	case KindChunk:
		if b, isC := body.(*ChunkBody); isC && len(b.Events) > 0 {
			return ChunkLID(h.Subj.SessionKey, m, b.Events[0].ID), true
		}
	case KindConclusion:
		if h.Prov == ProvMCPExplicit || h.Prov == ProvGateway {
			return ExplicitConclusionLID(owner, h.Subj.TaskID), true
		}
		if b, yes := body.(*ConclusionBody); yes && b.RequestKey != "" {
			return RequestConclusionLID(h.Subj.SessionKey, b.RequestKey), true
		}
	case KindTask:
		return TaskLID(owner, h.Subj.TaskID), true
	case KindCheckpoint:
		return CheckpointLID(owner, h.Subj.TaskID, m, h.Op), true
	case KindPause:
		return PauseLID(owner, h.Subj.TaskID, m, h.Op), true
	case KindCall:
		if b, isC := body.(*CallBody); isC {
			return CallLID(b.CallRef), true
		}
	case KindBinding:
		if b, isB := body.(*BindingBody); isB {
			return BindingLID(b.CallRef), true
		}
	case KindDigest:
		return DigestLID(h.Subj.SessionKey, m), true
	case KindRollup:
		return RollupLID(owner, h.Subj.TaskID, m), true
	case KindKeyOp:
		if b, isK := body.(*KeyOpBody); isK {
			return KeyLID(b.Subject.KeyID), true
		}
	case KindPolicy:
		if b, isP := body.(*PolicyBody); isP {
			return PolicyLID(b.Tenant), true
		}
	}
	return "", false
}

// SaltKeySize is the size of the device salt key.
const SaltKeySize = 32

// Salt returns base64url(HMAC-SHA256(key, JCS(["mnc1-salt", type, lid,
// body_jcs_without_salt]))[:16]) without padding.
func Salt(key []byte, k Kind, lid string, bodyJCSWithoutSalt []byte) (string, error) {
	if len(key) != SaltKeySize {
		return "", fmt.Errorf("salt: device salt key must be %d bytes", SaltKeySize)
	}
	msg, err := jcs.StringArray("mnc1-salt", string(k), lid, string(bodyJCSWithoutSalt))
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:16]), nil
}
