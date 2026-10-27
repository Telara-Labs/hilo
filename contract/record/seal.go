package record

import (
	"fmt"
	"github.com/Telara-Labs/hilo/contract/jcs"
	"unicode/utf8"
)

// SealText redacts the entire source before computing any digest or truncation.
// The caller clears raw parser buffers before persistence. This helper is not a
// complete record sealing/signing pipeline and stores no source digest.
func SealText(raw string, r Redactor, maxBytes int) Text {
	return boundText(r.Redact(raw), maxBytes)
}

func boundText(full string, maxBytes int) Text {
	cut := full
	if maxBytes < 0 {
		maxBytes = 0
	}
	if len(cut) > maxBytes {
		cut = cut[:maxBytes]
		for !utf8.ValidString(cut) && len(cut) > 0 {
			cut = cut[:len(cut)-1]
		}
	}
	return Text{Body: cut, Bytes: len(full), Truncated: cut != full}
}

// TaskMetadata copies only the declared source status, never inferred lifecycle.
func TaskMetadata(source TaskBody) *TaskMetaBody { return &TaskMetaBody{Status: source.Status} }

// MetadataBodyJCS provides the strict allowlist serialization shared by exporters.
func MetadataBodyJCS(body any) ([]byte, error) {
	switch body.(type) {
	case *TaskMetaBody, *SessionMetaBody:
		return jcs.MarshalRecord(body)
	}
	return nil, fmt.Errorf("metadata allowlist body required")
}
