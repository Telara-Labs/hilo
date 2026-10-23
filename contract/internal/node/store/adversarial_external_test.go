package store_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	"github.com/Telara-Labs/telara-memory/contract/jcs"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
)

// The signed extensions are valid at the pure parsing boundary. The adapter
// must refuse them before their bytes can reach a database, WAL or sidecar.
func TestRejectedControlExtensionsLeaveNoManagedBytes(t *testing.T) {
	ctx := context.Background()
	const machine = "1f111111-1111-4111-8111-111111111111"
	seed := sha256.Sum256([]byte("synthetic-control-extension-fixture"))
	key := ed25519.NewKeyFromSeed(seed[:])
	pub := key.Public().(ed25519.PublicKey)
	genesis, err := sig.BuildKeyOp(record.KeyOpBody{
		Op: record.OpGenesis, Genesis: sig.KeyID(pub),
		Subject: sig.KeyRefOf(pub, record.RoleDevice, machine),
	}, pub, machine, 1761150000000, key)
	if err != nil {
		t.Fatal(err)
	}
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(base, "node")
	s, err := store.Open(ctx, store.Options{Dir: dir, PinnedGenesisID: sig.KeyID(pub), LocalMachineID: machine})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if _, err = s.Append(ctx, extensionInput(t, genesis.Rec, key)); err != nil {
		t.Fatal(err)
	}
	absent := record.H("synthetic-absent-control-target")
	buildControl := func(kind record.Kind, body any) *record.Record {
		t.Helper()
		lid, err := record.ControlLID(kind, sig.KeyID(pub), "a1111111111111111111111111111111")
		if err != nil {
			t.Fatal(err)
		}
		r, err := record.Build(record.Header{
			Type: kind, LID: lid, At: 1761150000001, Prov: record.ProvUser,
			Author: record.Author{KeyID: sig.KeyID(pub), MachineID: machine},
			Red:    record.Redact{Profile: record.ProfileLocal},
		}, body, nil)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	erasure := buildControl(record.KindErasure, &record.ErasureBody{
		Selectors: record.Selectors{IDs: []string{absent}}, Reason: "user_request",
	})
	retraction := buildControl(record.KindRetraction, &record.RetractionBody{
		IDs: []string{absent}, Reason: "redaction_repair",
	})
	cases := []struct {
		name, nested string
		r            *record.Record
	}{
		{"key-top", "", genesis.Rec}, {"key-subject", "subject", genesis.Rec},
		{"erase-top", "", erasure}, {"erase-selector", "selectors", erasure},
		{"retract-top", "", retraction},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			canary := "CANARY_omitted_control_payload_" + tc.name + "_884e7e5271"
			var body map[string]any
			if err := json.Unmarshal(tc.r.BodyJCS, &body); err != nil {
				t.Fatal(err)
			}
			dst := body
			if tc.nested != "" {
				dst = body[tc.nested].(map[string]any)
			}
			dst["retained_extension"] = canary
			bodyJCS, err := jcs.MarshalRecord(body)
			if err != nil {
				t.Fatal(err)
			}
			h := tc.r.Header
			h.Body = &record.BodyRef{Digest: record.BodyDigest(bodyJCS), Size: int64(len(bodyJCS))}
			headerJCS, err := jcs.MarshalRecord(h)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := record.Parse(headerJCS, bodyJCS, "")
			if err != nil {
				t.Fatalf("fixture must cross pure parser %v", err)
			}
			in := extensionInput(t, parsed, key)
			before := append([]byte(nil), in.BodyJCS...)
			_, err = s.Append(ctx, in)
			if store.Code(err) != "non_minimal_control" || strings.Contains(err.Error(), canary) {
				t.Fatalf("unexpected refusal %v", err)
			}
			if !bytes.Equal(before, in.BodyJCS) {
				t.Fatal("adapter rewrote the signed body")
			}
			if tc.r.Header.Type != record.KindKeyOp {
				_, err = s.ApplyControl(ctx, in)
				if store.Code(err) != "non_minimal_control" {
					t.Fatalf("control entry bypassed retention gate %v", err)
				}
			}
			assertNoManagedCanary(t, dir, canary)
		})
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		assertNoManagedCanary(t, dir, "CANARY_omitted_control_payload_"+tc.name+"_884e7e5271")
	}
}

func extensionInput(t *testing.T, r *record.Record, key ed25519.PrivateKey) store.SignedRecord {
	t.Helper()
	signed, err := sig.SignRecord(key, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	return store.SignedRecord{HeaderJCS: r.HeaderJCS, BodyJCS: r.BodyJCS, Sigs: []record.Signature{signed}, AdvisoryID: r.ID}
}

func assertNoManagedCanary(t *testing.T, dir, canary string) {
	t.Helper()
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if !d.Type().IsRegular() {
			t.Fatalf("unexpected managed file type %s", path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(data, []byte(canary)) {
			t.Fatalf("rejected payload persisted in managed file %s", filepath.Base(path))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestUnsafeStoreAncestorsAndSidecarsRefusedBeforeSQLite(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("POSIX privacy boundary")
	}
	options := func(t *testing.T) store.Options {
		t.Helper()
		base, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		return store.Options{Dir: filepath.Join(base, "node"), PinnedGenesisID: "11111111111111111111111111111111", LocalMachineID: "1f111111-1111-4111-8111-111111111111"}
	}
	t.Run("untrusted-writable-ancestor", func(t *testing.T) {
		o := options(t)
		parent := filepath.Join(filepath.Dir(o.Dir), "shared")
		if err := os.Mkdir(parent, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(parent, 0777); err != nil {
			t.Fatal(err)
		}
		o.Dir = filepath.Join(parent, "private-node")
		if err := os.Mkdir(o.Dir, 0700); err != nil {
			t.Fatal(err)
		}
		s, err := store.Open(context.Background(), o)
		if s != nil {
			_ = s.Close()
		}
		if store.Code(err) != "unsafe_path" {
			t.Fatalf("unsafe ancestor admitted %v", err)
		}
		if _, err := os.Stat(filepath.Join(o.Dir, "memory.sqlite")); !os.IsNotExist(err) {
			t.Fatal("unsafe ancestor reached database creation")
		}
	})
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		t.Run("sidecar"+suffix, func(t *testing.T) {
			o := options(t)
			s, err := store.Open(context.Background(), o)
			if err != nil {
				t.Fatal(err)
			}
			if err = s.Close(); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(filepath.Dir(o.Dir), "outside-sentinel")
			want := []byte("owned synthetic sidecar target must stay unchanged")
			if err := os.WriteFile(target, want, 0600); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(o.Dir, "memory.sqlite"+suffix)
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			s, err = store.Open(context.Background(), o)
			if s != nil {
				_ = s.Close()
			}
			if store.Code(err) != "unsafe_path" {
				t.Errorf("unsafe sidecar reached SQLite %v", err)
			}
			got, err := os.ReadFile(target)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatal("unsafe sidecar target was touched")
			}
			info, err := os.Lstat(link)
			if err != nil || info.Mode()&os.ModeSymlink == 0 {
				t.Fatal("unsafe sidecar link was touched")
			}
		})
	}
}
