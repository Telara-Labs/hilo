package disclosure

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"testing"

	"github.com/Telara-Labs/hilo/contract/internal/node/store"
	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/sig"
)

func TestFacadeNextRefusalClosesOnlyUnidentifiedConnection(t *testing.T) {
	ctx := context.Background()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(base, "private")
	owner := sig.KeyID(pub)
	machine := "11111111-1111-4111-8111-111111111111"
	st, err := store.Open(ctx, store.Options{Dir: dir, PinnedGenesisID: owner, LocalMachineID: machine})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	genesis, err := sig.BuildKeyOp(record.KeyOpBody{Op: record.OpGenesis, Subject: sig.KeyRefOf(pub, record.RoleDevice, machine), Genesis: owner}, pub, machine, 1, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = st.Append(ctx, store.SignedRecord{HeaderJCS: genesis.Rec.HeaderJCS, BodyJCS: genesis.Rec.BodyJCS, Sigs: genesis.Sigs, AdvisoryID: genesis.Rec.ID}); err != nil {
		t.Fatal(err)
	}
	material, err := PreloadRuntimeMaterial(make([]byte, 32), key)
	if err != nil {
		t.Fatal(err)
	}
	defer material.Clear()
	service, err := New(ctx, st, Config{OwnerGenesis: owner, MachineID: machine}, material)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	admin, err := service.Administration(ctx)
	if err != nil {
		t.Fatal(err)
	}
	client, err := admin.Register(ctx, RegisterClient{AdminOpID: "lifecycle-register", ClientName: "test", ReadGrant: Grant{Repos: AllLocalRepos(), Channels: []Channel{S}}})
	if err != nil {
		t.Fatal(err)
	}
	token, err := client.Secret.Take()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(token)
	for _, identified := range []bool{false, true} {
		c, err := service.Authenticate(ctx, CredentialProof{CredentialID: client.CredentialID, Token: token})
		if err != nil {
			t.Fatal(err)
		}
		input := IdentityInput{}
		if identified {
			input.ConversationHandle = "lifecycle-conversation"
		}
		scope, err := c.Resolve(ctx, input)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = c.Next(ctx, scope, CallIdentity{}, "invalid cursor", ByteBudget{MaxBytes: 1}); err == nil {
			t.Fatal("invalid Next accepted")
		}
		if c.closed == identified {
			t.Fatal("wrong connection lifetime", identified, c.closed)
		}
		if identified {
			if _, err = c.IssueOperationTokens(ctx); err != nil {
				t.Fatal("identified retry state lost", err)
			}
		}
		c.Close()
	}
}
