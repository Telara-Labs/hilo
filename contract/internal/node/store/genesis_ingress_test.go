package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/Telara-Labs/hilo/contract/jcs"
	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/sig"
)

func ingressKeyOp(t *testing.T, b record.KeyOpBody, author ed25519.PrivateKey, machine string, signers ...ed25519.PrivateKey) SignedRecord {
	t.Helper()
	body, err := jcs.MarshalRecord(&b)
	if err != nil {
		t.Fatal(err)
	}
	h := record.Header{V: record.Version, Type: record.KindKeyOp, LID: record.KeyLID(b.Subject.KeyID), Author: record.Author{KeyID: sig.KeyID(author.Public().(ed25519.PublicKey)), MachineID: machine}, At: 1761150000000, Prov: record.ProvUser, Red: record.Redact{Profile: record.ProfileLocal}, Body: &record.BodyRef{Digest: record.BodyDigest(body), Size: int64(len(body))}}
	header, err := jcs.MarshalRecord(&h)
	if err != nil {
		t.Fatal(err)
	}
	in := SignedRecord{HeaderJCS: header, BodyJCS: body, AdvisoryID: record.ContentID(header)}
	for _, key := range signers {
		s, err := sig.SignRecord(key, in.AdvisoryID)
		if err != nil {
			t.Fatal(err)
		}
		in.Sigs = append(in.Sigs, s)
	}
	return in
}

func assertIngressWire(t *testing.T, want, got SignedRecord) {
	t.Helper()
	if got.AdvisoryID != want.AdvisoryID || !bytes.Equal(got.HeaderJCS, want.HeaderJCS) || !bytes.Equal(got.BodyJCS, want.BodyJCS) || !reflect.DeepEqual(got.Sigs, want.Sigs) {
		t.Fatal("node ingress changed original signed envelope")
	}
}

func TestOptionalGenesisSQLiteIngressStageRestartAndRetention(t *testing.T) {
	ctx := context.Background()
	for _, explicit := range []bool{false, true} {
		name := "omitted"
		if explicit {
			name = "explicit-self"
		}
		t.Run(name, func(t *testing.T) {
			key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{85}, 32))
			pub := key.Public().(ed25519.PublicKey)
			gid := sig.KeyID(pub)
			b := record.KeyOpBody{Op: record.OpGenesis, Subject: sig.KeyRefOf(pub, record.RoleDevice, testMachine)}
			if explicit {
				b.Genesis = gid
			}
			in := ingressKeyOp(t, b, key, testMachine, key)
			original := SignedRecord{HeaderJCS: append([]byte(nil), in.HeaderJCS...), BodyJCS: append([]byte(nil), in.BodyJCS...), Sigs: append([]record.Signature(nil), in.Sigs...), AdvisoryID: in.AdvisoryID}
			o := testOptions(t)
			o.PinnedGenesisID = gid
			s, err := Open(ctx, o)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { s.Close() })
			if err = s.VerifyStaged(ctx, []SignedRecord{in}); err != nil {
				t.Fatal(err)
			}
			if err = s.StageKeyOperation(ctx, in, nil); err != nil {
				t.Fatal(err)
			}
			if countRows(t, s, "SELECT count(*) FROM record") != 0 || countRows(t, s, "SELECT count(*) FROM key_restriction") != 1 {
				t.Fatal("staging committed activation or lost restriction")
			}
			var h, body, signatures []byte
			if err = s.conn.QueryRowContext(ctx, "SELECT header,body,sigs FROM key_restriction WHERE id=?", in.AdvisoryID).Scan(&h, &body, &signatures); err != nil {
				t.Fatal(err)
			}
			var sigs []record.Signature
			if err = json.Unmarshal(signatures, &sigs); err != nil {
				t.Fatal(err)
			}
			assertIngressWire(t, in, SignedRecord{HeaderJCS: h, BodyJCS: body, Sigs: sigs, AdvisoryID: in.AdvisoryID})
			reopenStore(t, &s, o)
			if status, err := s.DeviceKeyStatus(ctx, gid); err != nil || status != "" {
				t.Fatal("staged root activated before admission", status, err)
			}
			first, err := s.Append(ctx, in)
			if err != nil || first.ID != in.AdvisoryID || first.Sequence <= 0 {
				t.Fatal(first, err)
			}
			if countRows(t, s, "SELECT count(*) FROM key_restriction") != 0 {
				t.Fatal("admitted root retained its staging overlay")
			}
			if again, err := s.Append(ctx, in); err != nil || !again.Duplicate || again.Sequence != first.Sequence {
				t.Fatal("retry changed admission", again, err)
			}
			for restart := 0; restart < 2; restart++ {
				if status, err := s.DeviceKeyStatus(ctx, gid); err != nil || status != string(sig.KeyActive) {
					t.Fatal(status, err)
				}
				snap, err := s.Snapshot(ctx, ReadRequest{})
				if err != nil || len(snap.Entries) != 1 {
					t.Fatal(snap, err)
				}
				e := snap.Entries[0]
				if e.Owner != gid || e.State != "live" || e.SignatureStatus != string(sig.StatusVerified) {
					t.Fatal("genesis authority differs", e)
				}
				assertIngressWire(t, in, e.SignedRecord)
				kr, err := s.Keyring(ctx)
				if err != nil || len(kr) != 1 {
					t.Fatal("retained genesis omitted from keyring", kr, err)
				}
				assertIngressWire(t, in, kr[0])
				if _, err := s.SelectBundle(ctx, nil); Code(err) != "invalid_request" {
					t.Fatalf("empty selection must be rejected: %v", err)
				}
				sel, err := s.SelectBundle(ctx, []string{in.AdvisoryID})
				if err != nil || len(sel.Keyring) != 1 {
					t.Fatal("retained genesis omitted from selection", sel, err)
				}
				assertIngressWire(t, in, sel.Keyring[0])
				if err = s.VerifyStaged(ctx, []SignedRecord{in}); err != nil {
					t.Fatal(err)
				}
				reopenStore(t, &s, o)
			}
			receiverOptions := testOptions(t)
			receiverOptions.PinnedGenesisID = gid
			receiver, err := Open(ctx, receiverOptions)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { receiver.Close() })
			for n := 0; n < 2; n++ {
				report, err := receiver.ImportBundle(ctx, BundleImport{LocalKeyID: gid, Keyring: []SignedRecord{in}})
				if err != nil || report.Keyring != 1 {
					t.Fatal(report, err)
				}
				kr, err := receiver.Keyring(ctx)
				if err != nil || len(kr) != 1 {
					t.Fatal(kr, err)
				}
				assertIngressWire(t, in, kr[0])
			}
			assertIngressWire(t, original, in)
		})
	}
}

func TestGenesisSQLiteIngressRefusalsLeaveNoAuthorityOrRecords(t *testing.T) {
	ctx := context.Background()
	root := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{86}, 32))
	foreign := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{87}, 32))
	gid := sig.KeyID(root.Public().(ed25519.PublicKey))
	for _, mode := range []string{"foreign-root", "explicit-mismatch", "missing-possession", "foreign-signature", "foreign-device-domain", "missing-device-domain", "tenant-role"} {
		for _, route := range []string{"append", "import", "stage"} {
			t.Run(mode+"/"+route, func(t *testing.T) {
				b := record.KeyOpBody{Op: record.OpGenesis, Subject: sig.KeyRefOf(root.Public().(ed25519.PublicKey), record.RoleDevice, testMachine)}
				author, machine, signers := root, testMachine, []ed25519.PrivateKey{root}
				switch mode {
				case "foreign-root":
					b.Subject = sig.KeyRefOf(foreign.Public().(ed25519.PublicKey), record.RoleDevice, testMachine)
					author, signers = foreign, []ed25519.PrivateKey{foreign}
				case "explicit-mismatch":
					b.Genesis = sig.KeyID(foreign.Public().(ed25519.PublicKey))
				case "missing-possession":
					signers = nil
				case "foreign-signature":
					signers = []ed25519.PrivateKey{foreign}
				case "foreign-device-domain", "missing-device-domain":
					b.Op, b.Parents = record.OpDeviceAdd, []string{record.H("missing-parent")}
					b.Subject = sig.KeyRefOf(foreign.Public().(ed25519.PublicKey), record.RoleDevice, testMachine)
					signers = []ed25519.PrivateKey{foreign, root}
					b.Genesis = sig.KeyID(foreign.Public().(ed25519.PublicKey))
					if mode == "missing-device-domain" {
						b.Genesis = ""
					}
				case "tenant-role":
					b.Op, b.Genesis, b.Subject.Role, b.Subject.MachineID, machine = record.OpTenantKey, "acme", record.RoleService, "", ""
				}
				in := ingressKeyOp(t, b, author, machine, signers...)
				original := SignedRecord{HeaderJCS: append([]byte(nil), in.HeaderJCS...), BodyJCS: append([]byte(nil), in.BodyJCS...), Sigs: append([]record.Signature(nil), in.Sigs...), AdvisoryID: in.AdvisoryID}
				o := testOptions(t)
				o.PinnedGenesisID = gid
				s, err := Open(ctx, o)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { s.Close() })
				switch route {
				case "append":
					var result AdmissionResult
					result, err = s.Append(ctx, in)
					if result.ID != "" || result.Sequence != 0 {
						t.Fatal("refusal returned an admission acknowledgment", result)
					}
				case "import":
					var report BundleImportReport
					report, err = s.ImportBundle(ctx, BundleImport{LocalKeyID: gid, Keyring: []SignedRecord{in}})
					if report.Keyring != 0 {
						t.Fatal("refusal acknowledged imported authority", report)
					}
				case "stage":
					err = s.VerifyStaged(ctx, []SignedRecord{in})
					if err == nil {
						t.Fatal("invalid staged view accepted")
					}
					err = s.StageKeyOperation(ctx, in, nil)
				}
				if err == nil {
					t.Fatal("invalid ingress acknowledged")
				}
				assertIngressWire(t, original, in)
				if countRows(t, s, "SELECT count(*) FROM record") != 0 || countRows(t, s, "SELECT count(*) FROM key_restriction") != 0 {
					t.Fatal("refusal wrote authority")
				}
				reopenStore(t, &s, o)
				if status, err := s.DeviceKeyStatus(ctx, gid); err != nil || status != "" {
					t.Fatal("refusal activated root", status, err)
				}
				kr, err := s.Keyring(ctx)
				if err != nil || len(kr) != 0 {
					t.Fatal("refused ingress became exportable", kr, err)
				}
			})
		}
	}
}
