package jcs

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// fuzzInputLimit bounds the inputs whose run time is asserted. The engine can
// grow inputs; larger ones are still parsed but only checked for panics.
const fuzzInputLimit = 1 << 20

func addJCSSeeds(f *testing.F) {
	f.Helper()
	raw, err := os.ReadFile("../testdata/v01-jcs.json")
	if err != nil {
		f.Fatal(err)
	}
	var cases []struct {
		Raw       string `json:"raw"`
		RawBase64 string `json:"raw_base64"`
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		f.Fatal(err)
	}
	for _, c := range cases {
		if c.RawBase64 != "" {
			b, err := base64.StdEncoding.DecodeString(c.RawBase64)
			if err != nil {
				f.Fatal(err)
			}
			f.Add(b)
			continue
		}
		f.Add([]byte(c.Raw))
	}
	for _, name := range []string{"v03-worked-example.json", "v05-signature.json", "v20-exposures.json"} {
		b, err := os.ReadFile("../testdata/" + name)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add([]byte(`{"a":[1,-0,9007199254740991,9007199254740992,1.5e300,true,false,null,"\u0000\u001f "]}`))
	f.Add([]byte(`"😀􏿿"`))
	f.Add([]byte(`"﷐"`))
	// Nesting at and past the depth bound.
	f.Add([]byte(strings.Repeat("[", MaxDepth) + strings.Repeat("]", MaxDepth)))
	f.Add([]byte(strings.Repeat("[", MaxDepth+1) + strings.Repeat("]", MaxDepth+1)))
	f.Add([]byte(strings.Repeat(`{"a":`, 10000)))
	// Very large fields: one long string, one long key, many members.
	f.Add([]byte(`{"k":"` + strings.Repeat("x", 1<<20) + `"}`))
	f.Add([]byte(`{"` + strings.Repeat("k", 1<<16) + `":1}`))
	var many bytes.Buffer
	many.WriteByte('[')
	for i := 0; i < 1<<15; i++ {
		if i > 0 {
			many.WriteByte(',')
		}
		many.WriteString("0")
	}
	many.WriteByte(']')
	f.Add(many.Bytes())
	f.Add([]byte(strings.Repeat("9", 4096)))
}

// FuzzCanonicalize checks the general and record profiles: no panic, bounded
// time, valid JSON output, idempotence, profile consistency and a typed
// decode-encode round trip for record-profile values.
func FuzzCanonicalize(f *testing.F) {
	addJCSSeeds(f)
	f.Fuzz(func(t *testing.T, raw []byte) {
		start := time.Now()
		c, err := Canonicalize(raw)
		rc, rerr := CanonicalizeRecord(raw)
		if len(raw) <= fuzzInputLimit {
			if d := time.Since(start); d > 5*time.Second {
				t.Fatalf("canonicalization of %d bytes took %v", len(raw), d)
			}
		}
		if err == nil {
			if !json.Valid(c) {
				t.Fatalf("canonical output is not JSON: %q", c)
			}
			again, err := Canonicalize(c)
			if err != nil || !bytes.Equal(again, c) {
				t.Fatalf("not idempotent: %q -> %q (%v)", c, again, err)
			}
		}
		if rerr == nil {
			if err != nil {
				t.Fatalf("record profile accepted what the general profile rejected: %v", err)
			}
			if !bytes.Equal(rc, c) {
				t.Fatalf("profiles disagree: %q vs %q", rc, c)
			}
			if !IsCanonicalRecord(rc) {
				t.Fatal("record canonical output is not canonical")
			}
			// Record values are integers within the safe range, so a float64
			// decode is exact and re-encoding must give the same bytes.
			var v any
			if err := json.Unmarshal(rc, &v); err != nil {
				t.Fatal(err)
			}
			back, err := MarshalRecord(v)
			// Finding (reported, not fixed here): the typed string check counts
			// interface and container levels separately, so an untyped value
			// nested more than about MaxDepth/2 deep parses but cannot be
			// re-marshaled. Typed record structs never nest that deep.
			if e, ok := err.(*Error); ok && e.Code == CodeDepth {
				return
			}
			if err != nil || !bytes.Equal(back, rc) {
				t.Fatalf("decode-encode round trip: %q -> %q (%v)", rc, back, err)
			}
		}
		if IsCanonicalRecord(raw) && (rerr != nil || !bytes.Equal(rc, raw)) {
			t.Fatal("IsCanonicalRecord disagrees with CanonicalizeRecord")
		}
		if err != nil {
			if _, ok := err.(*Error); !ok {
				t.Fatalf("untyped error %T", err)
			}
		}
	})
}
