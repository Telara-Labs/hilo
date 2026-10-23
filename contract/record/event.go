package record

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/Telara-Labs/telara-memory/contract/jcs"
	"io"
	"sort"
)

// EventRevision is recomputable from a complete protected event body. The salt
// survives only in that body; indexes retain opaque revision IDs, never its salt.
func EventRevision(e Event) (string, error) {
	if !validEventSalt(e.Salt) {
		return "", fmt.Errorf("event: protected salt required")
	}
	e.Replaces = append([]string(nil), e.Replaces...)
	sort.Strings(e.Replaces)
	fields, err := eventFields(e)
	if err != nil {
		return "", err
	}
	delete(fields, "revision")
	b, err := jcs.MarshalRecord(fields)
	if err != nil {
		return "", err
	}
	return H("event-rev", e.ID, string(b)), nil
}
func eventFields(e Event) (map[string]json.RawMessage, error) {
	raw, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	err = json.Unmarshal(raw, &fields)
	return fields, err
}

// EventPayload is transient comparison material. Never persist it or an unsalted
// hash of it. Causal frontiers are checked separately when deriving aliases.
func EventPayload(e Event) ([]byte, error) {
	fields, err := eventFields(e)
	if err != nil {
		return nil, err
	}
	delete(fields, "revision")
	delete(fields, "salt")
	delete(fields, "replaces")
	return jcs.MarshalRecord(fields)
}
func validEventSalt(s string) bool {
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	return err == nil && len(b) == 16 && base64.RawURLEncoding.EncodeToString(b) == s
}

// ReviseEvent mints a NEW logical revision with fresh internal CSPRNG entropy.
// Unchanged retry/repack/transfer MUST copy the prior sealed event instead.
func ReviseEvent(e Event, predecessors []string, saltKey []byte) (Event, error) {
	return reviseEvent(e, predecessors, saltKey, rand.Reader)
}
func reviseEvent(e Event, predecessors []string, saltKey []byte, entropy io.Reader) (Event, error) {
	if len(saltKey) != SaltKeySize {
		return e, fmt.Errorf("event: salt key unavailable")
	}
	if len(predecessors) > 8 || !uniqueHex64(predecessors) {
		return e, fmt.Errorf("event: invalid predecessors")
	}
	e.Replaces = append([]string(nil), predecessors...)
	sort.Strings(e.Replaces)
	e.Salt = ""
	e.Revision = ""
	fields, err := eventFields(e)
	if err != nil {
		return e, err
	}
	delete(fields, "salt")
	delete(fields, "revision")
	payload, err := jcs.MarshalRecord(fields)
	if err != nil {
		return e, err
	}
	defer clear(payload)
	var nonce [32]byte
	if _, err = io.ReadFull(entropy, nonce[:]); err != nil {
		return e, fmt.Errorf("event: entropy unavailable")
	}
	msg, err := jcs.StringArray("mnc2-event-salt", e.ID, base64.RawURLEncoding.EncodeToString(nonce[:]), string(payload))
	if err != nil {
		return e, err
	}
	mac := hmac.New(sha256.New, saltKey)
	mac.Write(msg)
	e.Salt = base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:16])
	clear(nonce[:])
	clear(msg)
	e.Revision, err = EventRevision(e)
	return e, err
}

func TaskKey(owner, taskID string) (string, error) {
	if !ValidOwner(owner) || !IsUUID(taskID) {
		return "", fmt.Errorf("task: invalid owner or id")
	}
	b, err := jcs.StringArray(owner, taskID)
	return string(b), err
}
func NeedsErasureConfirmation(s Selectors, resolved, cumulative int64) bool {
	return len(s.Tasks)+len(s.Sessions)+len(s.LIDs)+len(s.Sources) > 0 || resolved > 1000 || cumulative > 1000 || resolved > 1000-cumulative
}
