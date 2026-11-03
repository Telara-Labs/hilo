package syncnode

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Telara-Labs/hilo/contract/internal/node/store"
	nodesync "github.com/Telara-Labs/hilo/contract/internal/node/sync"
	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/sig"
)

func TestInstalledEnrollmentGenesisPreservesOptionalAuthorityWire(t *testing.T) {
	ctx := context.Background()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{91}, 32))
	pub := key.Public().(ed25519.PublicKey)
	gid := sig.KeyID(pub)
	for _, explicit := range []bool{false, true} {
		name := "omitted"
		if explicit {
			name = "explicit-self"
		}
		t.Run(name, func(t *testing.T) {
			base, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(base, "data")
			o := store.Options{Dir: dir, PinnedGenesisID: gid, LocalMachineID: testMachine}
			st, err := store.Open(ctx, o)
			if err != nil {
				t.Fatal(err)
			}
			b := record.KeyOpBody{Op: record.OpGenesis, Subject: sig.KeyRefOf(pub, record.RoleDevice, testMachine)}
			if explicit {
				b.Genesis = gid
			}
			op, err := sig.BuildKeyOp(b, pub, testMachine, 1761150000000, key)
			if err != nil {
				st.Close()
				t.Fatal(err)
			}
			in := store.SignedRecord{HeaderJCS: op.Rec.HeaderJCS, BodyJCS: op.Rec.BodyJCS, Sigs: op.Sigs, AdvisoryID: op.Rec.ID}
			if _, err = st.Append(ctx, in); err != nil {
				st.Close()
				t.Fatal(err)
			}
			if err = st.Close(); err != nil {
				t.Fatal(err)
			}
			profile := Profile{Genesis: gid, Device: testMachine}
			for attempt := 0; attempt < 2; attempt++ {
				envelope, err := installedGenesis(ctx, dir, profile)
				if err != nil {
					t.Fatal(err)
				}
				r, err := nodesync.OpenEnvelope(envelope)
				if err != nil {
					t.Fatal(err)
				}
				if r.ID != in.AdvisoryID || !bytes.Equal(r.HeaderJCS, in.HeaderJCS) || !bytes.Equal(r.BodyJCS, in.BodyJCS) || !reflect.DeepEqual(envelope.Sigs, in.Sigs) || r.Body.(*record.KeyOpBody).Genesis != b.Genesis {
					t.Fatal("enrollment normalized retained genesis")
				}
				kr := sig.NewKeyring(gid)
				if res := sig.VerifyKeyOp(kr, &sig.KeyOp{Rec: r, Body: r.Body.(*record.KeyOpBody), Sigs: envelope.Sigs}); res.Err != nil || res.Status != sig.OpAuthorized {
					t.Fatal("returned envelope not independently possessed", res)
				}
			}
			foreign := profile
			foreign.Genesis = sig.KeyID(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{92}, 32)).Public().(ed25519.PublicKey))
			if envelope, err := installedGenesis(ctx, dir, foreign); err == nil || envelope.ID != "" {
				t.Fatal("foreign enrollment authority accepted", err)
			}
		})
	}
}

func TestInstalledEnrollmentGenesisCannotUseUnpossessedInput(t *testing.T) {
	ctx := context.Background()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{93}, 32))
	pub := key.Public().(ed25519.PublicKey)
	gid := sig.KeyID(pub)
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(base, "data")
	st, err := store.Open(ctx, store.Options{Dir: dir, PinnedGenesisID: gid, LocalMachineID: testMachine})
	if err != nil {
		t.Fatal(err)
	}
	op, err := sig.BuildKeyOp(record.KeyOpBody{Op: record.OpGenesis, Subject: sig.KeyRefOf(pub, record.RoleDevice, testMachine)}, pub, testMachine, 1761150000000)
	if err != nil {
		st.Close()
		t.Fatal(err)
	}
	if _, err = st.Append(ctx, store.SignedRecord{HeaderJCS: op.Rec.HeaderJCS, BodyJCS: op.Rec.BodyJCS, AdvisoryID: op.Rec.ID}); err == nil {
		st.Close()
		t.Fatal("unpossessed root admitted")
	}
	if err = st.Close(); err != nil {
		t.Fatal(err)
	}
	if envelope, err := installedGenesis(ctx, dir, Profile{Genesis: gid, Device: testMachine}); err == nil || envelope.ID != "" {
		t.Fatal("unpossessed root supplied enrollment", err)
	}
}
