package daemon

import (
	"encoding/json"
	"errors"
	"regexp"
	"time"

	tapredact "github.com/Telara-Labs/TAP-Runtime/discover/redact"
	"github.com/Telara-Labs/hilo/contract/internal/node/ipc"
	"github.com/Telara-Labs/hilo/contract/record"
)

type Native struct {
	Client string `json:"client"`
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Origin string `json:"origin"`
}
type Metadata struct {
	ProtocolVersion string          `json:"io.modelcontextprotocol/protocolVersion,omitempty"`
	Native          *Native         `json:"com.telara/native,omitempty"`
	Handle          string          `json:"com.telara/conversation,omitempty"`
	Legacy          string          `json:"com.telara/legacy-session-id,omitempty"`
	OpID            string          `json:"com.telara/op-id,omitempty"`
	Progress        json.RawMessage `json:"progressToken,omitempty"`
}

var asciiHandle = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
var clientToken = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
var errMetadataIdentity = errors.New("invalid_identity")

// Protocol metadata is validated separately from local identity. It is never
// installed authority, and capabilities are discarded before resolver/store use.
func validateProtocolMetadata(r Request, m Metadata) error {
	var params map[string]json.RawMessage
	_ = json.Unmarshal(r.Params, &params) // RequestParams already validated the envelope.
	var meta map[string]json.RawMessage
	_ = json.Unmarshal(params["_meta"], &meta)
	caps, hasCaps := meta["io.modelcontextprotocol/clientCapabilities"]
	_, hasInfo := meta["io.modelcontextprotocol/clientInfo"]
	modern := m.ProtocolVersion == LatestProtocolVersion
	// Discovery has no legacy initialization prerequisite. Inline modern fields
	// without a version must not silently downgrade to legacy processing either.
	if m.ProtocolVersion == "" && (r.Method == "server/discover" || hasCaps || hasInfo) {
		modern = true
	}
	if !modern {
		return nil
	}
	if m.ProtocolVersion == "" || !hasCaps || !validClientCapabilities(caps) {
		return errors.New("invalid_protocol_metadata")
	}
	return nil
}

func metadataObject(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	var fields map[string]json.RawMessage
	err := json.Unmarshal(raw, &fields)
	return fields, err == nil && fields != nil
}

// Validate the core ClientCapabilities object shape, including known nested
// objects. Unknown capabilities remain extension data and confer no authority.
func validClientCapabilities(raw json.RawMessage) bool {
	fields, ok := metadataObject(raw)
	if !ok {
		return false
	}
	for _, key := range []string{"roots", "sampling", "elicitation", "experimental", "extensions"} {
		v, present := fields[key]
		if !present {
			continue
		}
		children, ok := metadataObject(v)
		if !ok {
			return false
		}
		switch key {
		case "sampling", "elicitation":
			names := []string{"context", "tools"}
			if key == "elicitation" {
				names = []string{"form", "url"}
			}
			for _, name := range names {
				if value, present := children[name]; present {
					if _, ok := metadataObject(value); !ok {
						return false
					}
				}
			}
		case "experimental", "extensions":
			for _, value := range children {
				if _, ok := metadataObject(value); !ok {
					return false
				}
			}
		}
	}
	return true
}

func parseMetadata(raw []byte) (Metadata, error) {
	var m Metadata
	if len(raw) == 0 {
		return m, nil
	}
	if !validateEnvelope(raw) {
		return m, errMetadataIdentity
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return m, errMetadataIdentity
	}
	// Only these fields may influence local identity. Everything else, including
	// clientInfo, clientCapabilities and vendor tracing, is deliberately discarded.
	selected := make(map[string]json.RawMessage)
	for _, key := range []string{"com.telara/native", "com.telara/conversation", "com.telara/legacy-session-id", "com.telara/op-id", "progressToken"} {
		if v, ok := fields[key]; ok {
			if string(v) == "null" {
				return m, errMetadataIdentity
			}
			selected[key] = v
		}
	}
	if old, ok := fields["com.telara/conversation-handle"]; ok {
		var alias string
		if json.Unmarshal(old, &alias) != nil || !asciiHandle.MatchString(alias) || !safeIdentity("handle", alias) {
			return m, errMetadataIdentity
		}
		if current, ok := selected["com.telara/conversation"]; ok {
			var handle string
			if json.Unmarshal(current, &handle) != nil || handle != alias {
				return m, errMetadataIdentity
			}
		} else {
			selected["com.telara/conversation"] = old
		}
	}
	if v, ok := fields["io.modelcontextprotocol/protocolVersion"]; ok {
		if json.Unmarshal(v, &m.ProtocolVersion) != nil || string(v) == "null" || !validVersion(m.ProtocolVersion) {
			return m, errMetadataIdentity
		}
	}
	if rawNative, ok := selected["com.telara/native"]; ok {
		var nativeFields map[string]json.RawMessage
		if json.Unmarshal(rawNative, &nativeFields) != nil || len(nativeFields) != 4 {
			return m, errMetadataIdentity
		}
		for _, key := range []string{"client", "id", "kind", "origin"} {
			v, ok := nativeFields[key]
			var value string
			if !ok || string(v) == "null" || json.Unmarshal(v, &value) != nil {
				return m, errMetadataIdentity
			}
		}
	}
	filtered, _ := json.Marshal(selected)
	if ipc.DecodeStrict(filtered, &m) != nil {
		return m, errMetadataIdentity
	}
	if m.Native != nil {
		if !clientToken.MatchString(m.Native.Client) || !safeIdentity("native_client", m.Native.Client) || !asciiHandle.MatchString(m.Native.ID) || !safeIdentity("native_id", m.Native.ID) {
			return m, errMetadataIdentity
		}
		if m.Native.Kind != record.NativeLocal && m.Native.Kind != record.NativeGlobal {
			return m, errMetadataIdentity
		}
		if m.Native.Kind == record.NativeGlobal && !record.IsUUID(m.Native.ID) && !ulid.MatchString(m.Native.ID) {
			return m, errMetadataIdentity
		}
		if _, e := record.SessionKey(m.Native.Client, m.Native.Origin, m.Native.Kind, m.Native.ID, "12345678-1234-4234-8234-123456789abc"); e != nil {
			return m, errMetadataIdentity
		}
	}
	for key, value := range map[string]string{"com.telara/conversation": m.Handle, "com.telara/legacy-session-id": m.Legacy, "com.telara/op-id": m.OpID} {
		if _, present := fields[key]; present && (!asciiHandle.MatchString(value) || !safeIdentity(key, value)) {
			return m, errMetadataIdentity
		}
	}
	if len(m.Progress) > 0 && !ValidRPCID(m.Progress) {
		return m, errMetadataIdentity
	}

	return m, nil
}

var ulid = regexp.MustCompile(`^[0-7][0-9A-HJKMNP-TV-Z]{25}$`)

// RequestParams separates protocol metadata from method arguments, preserving
// original argument bytes and discarding all metadata not used for local identity.
func RequestParams(raw []byte) (json.RawMessage, Metadata, error) {
	var m Metadata
	if len(raw) == 0 {
		return json.RawMessage(`{}`), m, nil
	}
	if len(raw) > 1<<20 {
		return nil, m, errors.New("invalid_arguments")
	}
	if !validateEnvelope(raw) {
		return nil, m, errors.New("invalid_arguments")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return nil, m, errors.New("invalid_arguments")
	}
	var e error
	if v, ok := fields["_meta"]; ok {
		m, e = parseMetadata(v)
		if e != nil {
			return nil, m, e
		}
		delete(fields, "_meta")
	}
	args, e := json.Marshal(fields)
	return args, m, e
}
func validVersion(v string) bool { _, e := time.Parse("2006-01-02", v); return e == nil }
func safeIdentity(key, value string) bool {
	return tapredact.Redact(value) == value && tapredact.Argument(key, value) == value
}
