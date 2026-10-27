package bundle

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	"github.com/Telara-Labs/telara-memory/contract/jcs"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
)

func bundleIngressOp(t *testing.T, b record.KeyOpBody, key ed25519.PrivateKey, signers ...ed25519.PrivateKey) store.SignedRecord {
	t.Helper()
	body, err := jcs.MarshalRecord(&b)
	if err != nil {
		t.Fatal(err)
	}
	h := record.Header{V: record.Version, Type: record.KindKeyOp, LID: record.KeyLID(b.Subject.KeyID), Author: record.Author{KeyID: sig.KeyID(key.Public().(ed25519.PublicKey)), MachineID: b.Subject.MachineID}, At: 1761150000000, Prov: record.ProvUser, Red: record.Redact{Profile: record.ProfileLocal}, Body: &record.BodyRef{Digest: record.BodyDigest(body), Size: int64(len(body))}}
	header, err := jcs.MarshalRecord(&h)
	if err != nil {
		t.Fatal(err)
	}
	in := store.SignedRecord{HeaderJCS: header, BodyJCS: body, AdvisoryID: record.ContentID(header)}
	for _, key := range signers {
		s, err := sig.SignRecord(key, in.AdvisoryID)
		if err != nil {
			t.Fatal(err)
		}
		in.Sigs = append(in.Sigs, s)
	}
	return in
}

func assertBundleIngressWire(t *testing.T, want, got store.SignedRecord) {
	t.Helper()
	if want.AdvisoryID != got.AdvisoryID || !bytes.Equal(want.HeaderJCS, got.HeaderJCS) || !bytes.Equal(want.BodyJCS, got.BodyJCS) || !reflect.DeepEqual(want.Sigs, got.Sigs) {
		t.Fatal("bundle ingress changed signed envelope")
	}
}

func TestOptionalGenesisPublicBundleIngressAndReimport(t *testing.T) {
	ctx := context.Background()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{88}, 32))
	pub := key.Public().(ed25519.PublicKey)
	gid := sig.KeyID(pub)
	for _, explicit := range []bool{false, true} {
		name := "omitted"
		if explicit {
			name = "explicit-self"
		}
		t.Run(name, func(t *testing.T) {
			b := record.KeyOpBody{Op: record.OpGenesis, Subject: sig.KeyRefOf(pub, record.RoleDevice, fixtureMachine)}
			if explicit {
				b.Genesis = gid
			}
			in := bundleIngressOp(t, b, key, key)
			original := store.SignedRecord{HeaderJCS: append([]byte(nil), in.HeaderJCS...), BodyJCS: append([]byte(nil), in.BodyJCS...), Sigs: append([]record.Signature(nil), in.Sigs...), AdvisoryID: in.AdvisoryID}
			plain, _, err := Encode(store.BundleSelection{Keyring: []store.SignedRecord{in}}, gid, key, 1761150000001)
			if err != nil {
				t.Fatal(err)
			}
			c, err := Decode(plain, gid)
			if err != nil || len(c.Keyring) != 1 {
				t.Fatal(c, err)
			}
			assertBundleIngressWire(t, in, c.Keyring[0])
			if err = Verify(c, nil); err != nil {
				t.Fatal(err)
			}
			base, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			o := store.Options{Dir: filepath.Join(base, "data"), PinnedGenesisID: gid, LocalMachineID: fixtureMachine}
			st, err := store.Open(ctx, o)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { st.Close() })
			for pass := 0; pass < 2; pass++ {
				report, err := st.ImportBundle(ctx, store.BundleImport{LocalKeyID: gid, Keyring: c.Keyring})
				if err != nil || report.Keyring != 1 {
					t.Fatal(report, err)
				}
				local, err := st.Keyring(ctx)
				if err != nil || len(local) != 1 {
					t.Fatal(local, err)
				}
				assertBundleIngressWire(t, in, local[0])
				if err = Verify(c, local); err != nil {
					t.Fatal(err)
				}
				if _, err := st.SelectBundle(ctx, nil); store.Code(err) != "invalid_request" {
					t.Fatalf("empty selection must be rejected: %v", err)
				}
				selection, err := st.SelectBundle(ctx, []string{in.AdvisoryID})
				if err != nil || len(selection.Keyring) != 1 {
					t.Fatal(selection, err)
				}
				assertBundleIngressWire(t, in, selection.Keyring[0])
				forwarded, _, err := Encode(selection, gid, key, 1761150000002)
				if err != nil {
					t.Fatal(err)
				}
				c, err = Decode(forwarded, gid)
				if err != nil || len(c.Keyring) != 1 {
					t.Fatal(c, err)
				}
				if err = Verify(c, nil); err != nil {
					t.Fatal(err)
				}
				assertBundleIngressWire(t, in, c.Keyring[0])
				if err = st.Close(); err != nil {
					t.Fatal(err)
				}
				st, err = store.Open(ctx, o)
				if err != nil {
					t.Fatal(err)
				}
			}
			assertBundleIngressWire(t, original, in)
		})
	}
}

func TestOptionalGenesisBundleIngressRefusesForeignOrUnpossessedRoot(t *testing.T) {
	root := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{89}, 32))
	foreign := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{90}, 32))
	gid := sig.KeyID(root.Public().(ed25519.PublicKey))
	for _, mode := range []string{"foreign-root", "explicit-mismatch", "missing-possession", "foreign-signature", "missing-device-authority", "tenant-role"} {
		t.Run(mode, func(t *testing.T) {
			b := record.KeyOpBody{Op: record.OpGenesis, Subject: sig.KeyRefOf(root.Public().(ed25519.PublicKey), record.RoleDevice, fixtureMachine)}
			author, signers := root, []ed25519.PrivateKey{root}
			switch mode {
			case "foreign-root":
				b.Subject = sig.KeyRefOf(foreign.Public().(ed25519.PublicKey), record.RoleDevice, fixtureMachine)
				author, signers = foreign, []ed25519.PrivateKey{foreign}
			case "explicit-mismatch":
				b.Genesis = sig.KeyID(foreign.Public().(ed25519.PublicKey))
			case "missing-possession":
				signers = nil
			case "foreign-signature":
				signers = []ed25519.PrivateKey{foreign}
			case "missing-device-authority":
				b.Op, b.Parents = record.OpDeviceAdd, []string{record.H("absent-parent")}
			case "tenant-role":
				b.Op, b.Genesis, b.Subject.Role, b.Subject.MachineID = record.OpTenantKey, "acme", record.RoleService, ""
			}
			in := bundleIngressOp(t, b, author, signers...)
			header, body, signatures := append([]byte(nil), in.HeaderJCS...), append([]byte(nil), in.BodyJCS...), append([]record.Signature(nil), in.Sigs...)
			plain, _, err := Encode(store.BundleSelection{Keyring: []store.SignedRecord{in}}, gid, root, 1761150000001)
			if err == nil {
				c, decodeErr := Decode(plain, gid)
				err = decodeErr
				if err == nil {
					err = Verify(c, nil)
				}
			}
			if err == nil {
				t.Fatal("unsafe bundle became authorized")
			}
			if !bytes.Equal(header, in.HeaderJCS) || !bytes.Equal(body, in.BodyJCS) || !reflect.DeepEqual(signatures, in.Sigs) {
				t.Fatal("refusal changed received signed bytes")
			}
		})
	}
}
