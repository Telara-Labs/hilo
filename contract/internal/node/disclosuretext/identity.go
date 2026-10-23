package disclosuretext

import (
	"bytes"
	"encoding/json"
	"regexp"
	"unicode/utf8"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/localpolicy"
)

type IdentityKind string

const (
	ExternalOpID         IdentityKind = "external_op_id"
	AdminOpID            IdentityKind = "admin_op_id"
	ClientName           IdentityKind = "client_name"
	ConversationHandle   IdentityKind = "conversation_handle"
	ShimHandle           IdentityKind = "shim_handle"
	LegacySessionID      IdentityKind = "legacy_session_id"
	NativeAnnouncementID IdentityKind = "native_announcement_id"
	JSONRPCID            IdentityKind = "json_rpc_id"
)

var handleShape = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

func identityControl(r rune) bool {
	return r <= 0x1f || (r >= 0x7f && r <= 0x9f) || r == 0x61c || (r >= 0x200b && r <= 0x200f) || (r >= 0x202a && r <= 0x202e) || (r >= 0x2060 && r <= 0x206f) || r == 0xfeff
}

// ValidateIdentity never returns a replacement identity, value, or underlying
// helper error. Authentication secrets must NOT be passed to this text gate.
func ValidateIdentity(kind IdentityKind, value string) error {
	if !utf8.ValidString(value) || (value == "" && kind != JSONRPCID) {
		return fail("unsafe_identity")
	}
	switch kind {
	case ClientName:
		if len(value) > 128 {
			return fail("unsafe_identity")
		}
		for _, r := range value {
			if identityControl(r) {
				return fail("unsafe_identity")
			}
		}
	case ExternalOpID, AdminOpID, ConversationHandle, ShimHandle, LegacySessionID, NativeAnnouncementID:
		if !handleShape.MatchString(value) {
			return fail("unsafe_identity")
		}
	case JSONRPCID:
		if len(value) > 256 {
			return fail("unsafe_identity")
		}
	default:
		return fail("unsafe_identity")
	}
	if localpolicy.Text(value) != value || localpolicy.Argument(string(kind), value) != value {
		return fail("unsafe_identity")
	}
	return nil
}

// CanonicalRPCID checks complete decoded AND encoded scalar forms before any
// frozen identity helper. An unsafe ID must be represented as null by a future
// transport, never echoed using these errors. Null is not an accepted call ID.
func CanonicalRPCID(raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw) > 256 {
		return nil, fail("unsafe_identity")
	}
	c, e := strictJSON(raw)
	if e != nil || len(c) > 256 {
		return nil, fail("unsafe_identity")
	}
	if c[0] == '"' {
		var s string
		if json.Unmarshal(c, &s) != nil || ValidateIdentity(JSONRPCID, s) != nil {
			return nil, fail("unsafe_identity")
		}
	} else if c[0] == '-' || (c[0] >= '0' && c[0] <= '9') {
		if ValidateIdentity(JSONRPCID, string(bytes.TrimSpace(raw))) != nil {
			return nil, fail("unsafe_identity")
		}
	} else {
		return nil, fail("unsafe_identity")
	}
	if ValidateIdentity(JSONRPCID, string(c)) != nil {
		return nil, fail("unsafe_identity")
	}
	return append([]byte(nil), c...), nil
}
