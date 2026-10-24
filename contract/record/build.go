package record

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"reflect"

	"github.com/Telara-Labs/telara-memory/contract/jcs"
)

// Build constructs a NEW private candidate using independent internal CSPRNG
// secrets. Runtime adapters must resolve durable settlement and authority before
// calling it, commit before exposure, and copy exact committed seals on retries.
// Legacy key arguments are rejected, never used as entropy. Salt/hash overrides
// are not authoring inputs. Imported seals use Parse instead.
func Build(h Header, body any, legacyKey ...[]byte) (*Record, error) {
	if len(legacyKey) != 0 {
		return nil, fmt.Errorf("build: caller key override forbidden")
	}
	return build(h, body, rand.Reader, false)
}

func build(h Header, body any, entropy io.Reader, callPrepared bool) (*Record, error) {
	if body == nil || reflect.ValueOf(body).Kind() != reflect.Pointer || reflect.ValueOf(body).IsNil() {
		return nil, fmt.Errorf("build: typed body pointer required")
	}
	// Work on a private copy. Failure never publishes a partly salted caller body.
	copyBody := newBody(BodyTypeName(h.Type, h.Prov))
	if reflect.TypeOf(copyBody) != reflect.TypeOf(body) {
		return nil, fmt.Errorf("build: wrong body type")
	}
	// Validate the original typed strings, including nested map keys, before
	// encoding/json can replace invalid UTF-8. Use general JCS for the copy:
	// authoring has not yet filled required salts or normalized absent fields.
	raw, err := jcs.Marshal(body)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	if err = json.Unmarshal(raw, copyBody); err != nil {
		return nil, err
	}
	body = copyBody
	if chunk, ok := body.(*ChunkBody); ok {
		for i, e := range chunk.Events {
			if e.Revision == "" {
				v, err := reviseEvent(e, e.Replaces, entropy)
				if err != nil {
					return nil, err
				}
				chunk.Events[i] = v
			}
		}
	}
	if salted(h.Type) {
		salt, _ := saltOf(body)
		if salt != "" && !callPrepared {
			return nil, fmt.Errorf("build: caller salt override forbidden")
		}
		if c, ok := body.(*CallBody); ok && !callPrepared && (c.ArgsHash != "" || c.ResultHash != "") {
			return nil, fmt.Errorf("build: caller commitment override forbidden")
		}
		if !callPrepared {
			salt, err = newSecret(entropy)
			if err != nil {
				return nil, err
			}
			setSalt(body, salt)
		}
	}
	bodyJCS, err := jcs.MarshalRecord(body)
	if err != nil {
		return nil, err
	}
	h.V = Version
	h.Body = &BodyRef{Digest: BodyDigest(bodyJCS), Size: int64(len(bodyJCS))}
	headerJCS, err := jcs.MarshalRecord(&h)
	if err != nil {
		return nil, err
	}
	return Parse(headerJCS, bodyJCS, "")
}

func newSecret(entropy io.Reader) (string, error) {
	var secret [16]byte
	defer clear(secret[:])
	if _, err := io.ReadFull(entropy, secret[:]); err != nil {
		return "", fmt.Errorf("entropy unavailable")
	}
	return base64.RawURLEncoding.EncodeToString(secret[:]), nil
}

// BuildCall seals declared complete dependencies and redacted JSON VALUES under
// one fresh body-only key. nil values mean unavailable, never an empty-input hash.
func BuildCall(h Header, body CallBody, args, result json.RawMessage) (*Record, error) {
	if h.Type != KindCall || body.Salt != "" || body.ArgsHash != "" || body.ResultHash != "" {
		return nil, fmt.Errorf("call: authoring override forbidden")
	}
	salt, err := newSecret(rand.Reader)
	if err != nil {
		return nil, err
	}
	body.Salt = salt
	if args != nil {
		body.ArgsHash, err = CallCommitment(salt, "args", body.Tool, args)
		if err != nil {
			return nil, err
		}
	}
	if result != nil {
		body.ResultHash, err = CallCommitment(salt, "result", body.Tool, result)
		if err != nil {
			return nil, err
		}
	}
	return build(h, &body, rand.Reader, true)
}

// WithoutBody returns a copy of r whose body bytes are absent, as after a
// body purge. The id is unchanged because it covers the body only through
// header.body.digest.
func (r *Record) WithoutBody() *Record {
	c := *r
	c.BodyJCS = nil
	c.Body = nil
	return &c
}
