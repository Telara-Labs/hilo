package record

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/Telara-Labs/hilo/contract/jcs"
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
	raw, err := jcs.MarshalRecord(e)
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
	if err := ValidateEventText(e); err != nil {
		return nil, err
	}
	if e.Result != nil && e.Result.Bytes > len(e.Result.Excerpt) {
		return nil, fmt.Errorf("event: complete result unavailable")
	}
	if e.Text != nil && e.Text.Truncated {
		return nil, fmt.Errorf("event: complete text unavailable")
	}
	fields, err := eventFields(e)
	if err != nil {
		return nil, err
	}
	if e.Text != nil {
		text := *e.Text
		text.Digest = ""
		raw, err := json.Marshal(text)
		if err != nil {
			return nil, err
		}
		fields["text"] = raw
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
// Unchanged committed or exposed retry/repack/transfer MUST copy the prior seal.
// A private uncommitted candidate may be rebuilt only after the runtime proves
// noncommit from recovered same-store transition history. Unknown settlement or
// an unavailable committed body never permits resealing.
func ReviseEvent(e Event, predecessors []string, legacyKey ...[]byte) (Event, error) {
	if len(legacyKey) != 0 {
		return Event{}, fmt.Errorf("event: caller key forbidden")
	}
	return reviseEvent(e, predecessors, rand.Reader)
}
func reviseEvent(e Event, predecessors []string, entropy io.Reader) (Event, error) {
	if e.Salt != "" || e.Revision != "" || e.Text != nil && e.Text.Digest != "" {
		return Event{}, fmt.Errorf("event: authoring seal override forbidden")
	}
	if len(predecessors) > 8 || !uniqueHex64(predecessors) {
		return Event{}, fmt.Errorf("event: invalid predecessors")
	}
	e.Replaces = append([]string(nil), predecessors...)
	sort.Strings(e.Replaces)
	salt, err := newSecret(entropy)
	if err != nil {
		return Event{}, err
	}
	e.Salt = salt
	e.Revision, err = EventRevision(e)
	if err != nil {
		return Event{}, err
	}
	return e, nil
}

// ReviseTextEvent redacts the full value, draws its private event secret, then
// computes the declared keyed digest before display truncation.
func ReviseTextEvent(e Event, predecessors []string, raw string, redactor Redactor, maxBytes int) (Event, error) {
	return reviseTextEvent(e, predecessors, raw, redactor, maxBytes, rand.Reader)
}
func reviseTextEvent(e Event, predecessors []string, raw string, redactor Redactor, maxBytes int, entropy io.Reader) (Event, error) {
	if e.Text != nil || redactor == nil {
		return Event{}, fmt.Errorf("event: text override forbidden")
	}
	e.Text = &Text{}
	sealed, err := reviseEvent(e, predecessors, entropy)
	if err != nil {
		return Event{}, err
	}
	full := redactor.Redact(raw)
	text := boundText(full, maxBytes)
	text.Digest, err = EventTextCommitment(sealed.Salt, full)
	if err != nil {
		return Event{}, err
	}
	sealed.Text = &text
	sealed.Revision, err = EventRevision(sealed)
	return sealed, err
}

// ValidateEventText checks a declared digest when the full text is available.
// A truncated body never proves its hidden preimage and cannot form equality.
func ValidateEventText(e Event) error {
	if e.Text == nil {
		return nil
	}
	t := e.Text
	if !t.Truncated && t.Bytes > 0 && t.Bytes != len(t.Body) {
		return fmt.Errorf("event: incomplete untruncated text")
	}
	if t.Bytes < 0 || t.Bytes > 0 && t.Bytes < len(t.Body) || t.Digest != "" && !IsHex64(t.Digest) {
		return fmt.Errorf("event: text shape")
	}
	if t.Digest != "" && !t.Truncated {
		digest, err := EventTextCommitment(e.Salt, t.Body)
		if err != nil || digest != t.Digest {
			return fmt.Errorf("event: text commitment mismatch")
		}
	}
	return nil
}

func TaskKey(owner, taskID string) (string, error) {
	if !ValidOwner(owner) || !IsUUID(taskID) {
		return "", fmt.Errorf("task: invalid owner or id")
	}
	b, err := jcs.StringArray(owner, taskID)
	return string(b), err
}
func NeedsErasureConfirmation(s Selectors, resolved, cumulative int64) bool {
	return len(s.Events)+len(s.Tasks)+len(s.Sessions)+len(s.LIDs)+len(s.Sources) > 0 || resolved > 1000 || cumulative > 1000 || resolved > 1000-cumulative
}
