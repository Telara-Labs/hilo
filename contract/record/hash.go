package record

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/Telara-Labs/hilo/contract/jcs"
)

// H returns lowercase hex(sha256(JCS(["mnc1", tag, parts...]))). The JSON
// array makes the concatenation unambiguous. It panics only if a part is not
// valid UTF-8 or holds a noncharacter, which callers prevent by building parts
// from identifiers; use HE to get the error instead.
func H(tag string, parts ...string) string {
	s, err := HE(tag, parts...)
	if err != nil {
		panic(err)
	}
	return s
}

// HE is H returning an error for parts that cannot be canonicalized.
func HE(tag string, parts ...string) (string, error) {
	all := append([]string{"mnc1", tag}, parts...)
	b, err := jcs.StringArray(all...)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// NativeIDKind values.
const (
	NativeGlobal = "global" // a UUID or ULID the client mints
	NativeLocal  = "local"  // file stem, path-derived or synthetic
)

// Origin of a session for SessionKey: "local" or "cloud:<vendor>".
var originRe = regexp.MustCompile(`^(local|cloud:[a-z0-9][a-z0-9-]{0,62})$`)

// SessionKey returns "sk1:" + H("sk1", client_id, origin, scoped_native_id),
// where scoped_native_id is nativeID for a global id and
// machineID + "/" + nativeID for a local one.
func SessionKey(clientID, origin, nativeIDKind, nativeID, machineID string) (string, error) {
	if clientID == "" || nativeID == "" {
		return "", fmt.Errorf("session key: client id and native id are required")
	}
	if !originRe.MatchString(origin) {
		return "", fmt.Errorf("session key: origin %q is not local or cloud:<vendor>", origin)
	}
	scoped := nativeID
	switch nativeIDKind {
	case NativeGlobal:
	case NativeLocal:
		if !IsUUID(machineID) {
			return "", fmt.Errorf("session key: a local native id needs the machine id")
		}
		scoped = machineID + "/" + nativeID
	default:
		return "", fmt.Errorf("session key: native id kind %q is not global or local", nativeIDKind)
	}
	h, err := HE("sk1", clientID, origin, scoped)
	if err != nil {
		return "", err
	}
	return "sk1:" + h, nil
}

// RepoID returns "r1:" + hex(sha256(normalizedRemote)). The remote must
// already be normalized (no userinfo, query, fragment or ".git").
func RepoID(normalizedRemote string) (string, error) {
	if normalizedRemote == "" {
		return "", fmt.Errorf("repo id: empty remote")
	}
	if strings.ContainsAny(normalizedRemote, "@?#") || strings.HasSuffix(normalizedRemote, ".git") {
		return "", fmt.Errorf("repo id: remote %q is not normalized", normalizedRemote)
	}
	sum := sha256.Sum256([]byte(normalizedRemote))
	return "r1:" + hex.EncodeToString(sum[:]), nil
}

// RepoIDLocal returns "r1l:" + H("r1l", machine_id, abs_toplevel) for a
// repository without a remote.
func RepoIDLocal(machineID, absToplevel string) (string, error) {
	if !IsUUID(machineID) || absToplevel == "" {
		return "", fmt.Errorf("local repo id: machine id and top-level path are required")
	}
	h, err := HE("r1l", machineID, absToplevel)
	if err != nil {
		return "", err
	}
	return "r1l:" + h, nil
}

// SourceKey returns H("src", client_id, machine_id, home_relative_path_or_db_key).
func SourceKey(clientID, machineID, unit string) (string, error) {
	if clientID == "" || !IsUUID(machineID) || unit == "" {
		return "", fmt.Errorf("source key: client id, machine id and unit are required")
	}
	return HE("src", clientID, machineID, unit)
}

// Anchor is the input of an event id. Exactly one form is used: the native
// form when the client gives the item an id, else the positional form. Every
// field of the chosen form is always present in the hashed JSON, zero values
// included (see OPEN-QUESTIONS Q10).
type Anchor struct {
	NativeItemID string // native form when non-empty
	Path         string // positional form
	Line         int64
	Block        int64
	Inner        int64 // ordinal of an inner call inside one source item
	Part         int64
}

func (a Anchor) jcs() (string, error) {
	if a.Inner < 0 || a.Part < 0 || a.Line < 0 || a.Block < 0 {
		return "", fmt.Errorf("event anchor: negative ordinal")
	}
	var b []byte
	var err error
	if a.NativeItemID != "" {
		if a.Path != "" || a.Line != 0 || a.Block != 0 {
			return "", fmt.Errorf("event anchor: native and positional fields mixed")
		}
		b, err = jcs.MarshalRecord(struct {
			NativeItemID string `json:"native_item_id"`
			Inner        int64  `json:"inner"`
			Part         int64  `json:"part"`
		}{a.NativeItemID, a.Inner, a.Part})
	} else {
		if a.Path == "" {
			return "", fmt.Errorf("event anchor: neither a native item id nor a path")
		}
		b, err = jcs.MarshalRecord(struct {
			Path  string `json:"path"`
			Line  int64  `json:"line"`
			Block int64  `json:"block"`
			Inner int64  `json:"inner"`
			Part  int64  `json:"part"`
		}{a.Path, a.Line, a.Block, a.Inner, a.Part})
	}
	return string(b), err
}

// EventID returns "ev1:" + H("ev1", session_key, event_kind, anchor_jcs).
// It is never a content hash.
func EventID(sessionKey, eventKind string, a Anchor) (string, error) {
	if !IsSessionKey(sessionKey) || !eventKinds[eventKind] {
		return "", fmt.Errorf("event id: bad session key or event kind %q", eventKind)
	}
	anchor, err := a.jcs()
	if err != nil {
		return "", err
	}
	h, err := HE("ev1", sessionKey, eventKind, anchor)
	if err != nil {
		return "", err
	}
	return "ev1:" + h, nil
}

var callRefEnc = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewCallRef returns "m1." + 10 lowercase base32 characters (RFC 4648
// alphabet) carrying 50 random bits from the internal CSPRNG.
func NewCallRef(legacyEntropy ...io.Reader) (string, error) {
	if len(legacyEntropy) != 0 {
		return "", fmt.Errorf("caller entropy forbidden")
	}
	return newCallRef(rand.Reader)
}
func newCallRef(r io.Reader) (string, error) {
	var b [7]byte // 56 bits read; the low 6 are dropped
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return "", err
	}
	b[6] &= 0xC0
	s := strings.ToLower(callRefEnc.EncodeToString(b[:]))
	return "m1." + s[:10], nil
}

// OpID refuses the retired content-hash operation construction.
func OpID(scopeID, requestIdentity, tool, argsHash string) (string, error) {
	return "", fmt.Errorf("content-derived operation identities forbidden")
}

var callerOpIDRe = regexp.MustCompile(`^op1:[0-9a-f]{32}$`)

func ValidCallerOpID(s string) bool { return callerOpIDRe.MatchString(s) }

// SuppliedOpID cannot establish issuance from syntax. Use OperationTokens.Resolve
// against the durable credential-bound receiver ledger instead.
func SuppliedOpID(credential, token string) (string, error) {
	return "", fmt.Errorf("node issuance ledger required")
}

// FallbackOpID accepts only receiver-minted opaque protocol identities. The RPC
// argument is a receiver token, never the wire id or a hash of content/wire bytes.
func FallbackOpID(credential, scopeID, connectionID, requestToken, tool string) (string, error) {
	parts := strings.Split(scopeID, ":")
	if credential == "" || len(parts) != 3 || !ValidScopeID(scopeID, parts[1]) || !IsKeyID(connectionID) || !IsKeyID(requestToken) || !ValidReceiptTool(tool) {
		return "", fmt.Errorf("invalid fallback identities")
	}
	return HE("op", credential, scopeID, connectionID, requestToken, tool)
}
func RequestIdentityMeta(opID string) (string, error) {
	return "", fmt.Errorf("node issuance ledger required")
}
func RequestIdentityRPC(connectionID string, rpcID []byte) (string, error) {
	return "", fmt.Errorf("wire RPC identity is erasable connection state")
}

// Format checks shared by the package.

var (
	hex64Re      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	hex32Re      = regexp.MustCompile(`^[0-9a-f]{32}$`)
	uuidRe       = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	uuidV4Re     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	sessionKeyRe = regexp.MustCompile(`^sk1:[0-9a-f]{64}$`)
	repoIDRe     = regexp.MustCompile(`^(r1|r1l):[0-9a-f]{64}$`)
	eventIDRe    = regexp.MustCompile(`^ev1:[0-9a-f]{64}$`)
	callRefRe    = regexp.MustCompile(`^m1\.[a-z2-7]{10}$`)
	saltRe       = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)
	tokenRe      = regexp.MustCompile(`^[A-Za-z0-9._:+/-]{1,128}$`)
)

// IsHex64 reports a 64-character lowercase hex string (ids, lids, digests).
func IsHex64(s string) bool { return hex64Re.MatchString(s) }

// IsKeyID reports a 32-character lowercase hex key id.
func IsKeyID(s string) bool { return hex32Re.MatchString(s) }

// IsUUID reports a lowercase RFC 9562 UUID string of any defined version.
func IsUUID(s string) bool { return uuidRe.MatchString(s) }

// IsUUIDv4 reports a lowercase version-4 UUID string.
func IsUUIDv4(s string) bool { return uuidV4Re.MatchString(s) }

// IsSessionKey reports "sk1:" + 64 hex.
func IsSessionKey(s string) bool { return sessionKeyRe.MatchString(s) }

// IsRepoID reports "r1:" or "r1l:" + 64 hex.
func IsRepoID(s string) bool { return repoIDRe.MatchString(s) }

// IsEventID reports "ev1:" + 64 hex.
func IsEventID(s string) bool { return eventIDRe.MatchString(s) }

// IsCallRef reports "m1." + 10 lowercase base32 characters.
func IsCallRef(s string) bool { return callRefRe.MatchString(s) }

// isToken reports a short printable identifier without spaces.
func isToken(s string) bool { return tokenRe.MatchString(s) }

// pageString renders a session page number as used in the session LID.
func pageString(p int64) string { return strconv.FormatInt(p, 10) }
