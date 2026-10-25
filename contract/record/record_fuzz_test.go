package record_test

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/jcs"
	"github.com/Telara-Labs/telara-memory/contract/record"
)

type headerBodyFixture struct {
	HeaderJCS string `json:"HeaderJCS"`
	BodyJCS   string `json:"BodyJCS"`
}

func addRecordSeeds(f *testing.F) {
	f.Helper()
	for _, name := range []string{"../testdata/v03-records.json", "../testdata/historical-mnc2/v03-records.json"} {
		raw, err := os.ReadFile(name)
		if err != nil {
			f.Fatal(err)
		}
		var fs []headerBodyFixture
		if err := json.Unmarshal(raw, &fs); err != nil {
			f.Fatal(err)
		}
		for _, x := range fs {
			f.Add([]byte(x.HeaderJCS), []byte(x.BodyJCS), true)
			f.Add([]byte(x.HeaderJCS), []byte(nil), false)
		}
	}
	for _, name := range []string{"../testdata/v03-worked-example.json", "../testdata/v05-signature.json"} {
		raw, err := os.ReadFile(name)
		if err != nil {
			f.Fatal(err)
		}
		var x struct {
			Header string `json:"header_jcs"`
			Body   string `json:"body_jcs"`
		}
		if err := json.Unmarshal(raw, &x); err != nil {
			f.Fatal(err)
		}
		f.Add([]byte(x.Header), []byte(x.Body), true)
	}
	// Bounds: oversized header and body, deep nesting, huge string member.
	f.Add(bytes.Repeat([]byte{' '}, record.MaxHeaderBytes+1), []byte(nil), false)
	f.Add([]byte(`{"v":3}`), bytes.Repeat([]byte{'['}, record.MaxBodyBytes+1), true)
	f.Add([]byte(`{"v":3,"type":"conclusion","lid":"`+strings.Repeat("a", 1<<16)+`"}`), []byte(`{}`), true)
	f.Add([]byte(`{"v":3}`), []byte(strings.Repeat("[", 1000)), true)
	f.Add([]byte(`{"v":4,"type":"future"}`), []byte(nil), false)
	f.Add([]byte(`{"v":9007199254740992}`), []byte(nil), false)
}

// FuzzRecordParse decodes arbitrary header and body bytes through record
// admission. Accepted records must be canonical, self-identifying and
// stable under a second parse and a typed decode-encode round trip.
func FuzzRecordParse(f *testing.F) {
	addRecordSeeds(f)
	f.Fuzz(func(t *testing.T, header, body []byte, hasBody bool) {
		if !hasBody {
			body = nil
		}
		start := time.Now()
		r, err := record.Parse(header, body, "")
		if d := time.Since(start); d > 5*time.Second {
			t.Fatalf("parse took %v for %d+%d bytes", d, len(header), len(body))
		}
		if err != nil {
			if record.CodeOf(err) == "" {
				t.Fatalf("admission error without a code: %v", err)
			}
			return
		}
		if r.ID != record.ContentID(header) || !bytes.Equal(r.HeaderJCS, header) || !jcs.IsCanonicalRecord(header) {
			t.Fatal("accepted header is not its own canonical identity")
		}
		if r.Header.V != record.Version {
			t.Fatalf("accepted version %d", r.Header.V)
		}
		again, err := jcs.MarshalRecord(&r.Header)
		if err != nil || !bytes.Equal(again, header) {
			t.Fatal("header decode-encode round trip differs")
		}
		if body != nil {
			if r.Header.Body == nil || record.BodyDigest(body) != r.Header.Body.Digest || int64(len(body)) != r.Header.Body.Size {
				t.Fatal("accepted body does not match its reference")
			}
			if r.Body == nil {
				t.Fatal("accepted body was not decoded")
			}
			enc, err := jcs.MarshalRecord(r.Body)
			if err != nil || !bytes.Equal(enc, body) {
				t.Fatal("body decode-encode round trip differs")
			}
		}
		second, err := record.Parse(header, body, r.ID)
		if err != nil || second.ID != r.ID {
			t.Fatalf("second parse disagrees: %v", err)
		}
		if _, err := record.Parse(header, body, strings.Repeat("0", 64)); err == nil && r.ID != strings.Repeat("0", 64) {
			t.Fatal("wrong advisory id accepted")
		}
	})
}
