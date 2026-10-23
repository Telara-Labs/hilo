package disclosure

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestZeroFacadeCapabilitiesFailClosed(t *testing.T) {
	ctx := context.Background()
	var service Service
	var connection Connection
	var reply Reply
	var admin Administration
	if _, e := service.Administration(ctx); e == nil {
		t.Fatal("zero service admin")
	}
	if _, e := service.Authenticate(ctx, CredentialProof{}); e == nil {
		t.Fatal("zero service authentication")
	}
	if _, e := connection.Resolve(ctx, IdentityInput{}); e == nil {
		t.Fatal("zero connection scope")
	}
	if _, e := connection.Execute(ctx, RequestScope{}, CallIdentity{}, Command{}, ByteBudget{}); e == nil {
		t.Fatal("zero connection execute")
	}
	if _, e := connection.Next(ctx, RequestScope{}, CallIdentity{}, "", ByteBudget{}); e == nil {
		t.Fatal("zero connection next")
	}
	if _, e := connection.Acknowledge(ctx, ACK{}); e == nil {
		t.Fatal("zero connection ACK")
	}
	if _, e := reply.Release(ctx); e == nil {
		t.Fatal("zero reply release")
	}
	if _, e := admin.Register(ctx, RegisterClient{}); e == nil {
		t.Fatal("zero administrator register")
	}
	if _, e := admin.ReplaceGrant(ctx, "", "", 0, Grant{}); e == nil {
		t.Fatal("zero administrator grant")
	}
	if _, e := admin.ReplaceTaskWrites(ctx, "", "", 0, TaskWriteGrant{}); e == nil {
		t.Fatal("zero administrator write")
	}
	if _, e := admin.RotateCredential(ctx, "", "", 0); e == nil {
		t.Fatal("zero administrator rotate")
	}
	if _, e := admin.RevokeCredential(ctx, "", "", 0); e == nil {
		t.Fatal("zero administrator revoke")
	}
	if service.Close() != nil || connection.Close() != nil {
		t.Fatal("zero close")
	}
}

func TestFacadeMaterialRequiresConcreteConsistentKey(t *testing.T) {
	_, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(private)
	salt := make([]byte, 32)
	salt[0] = 1
	material, e := PreloadRuntimeMaterial(salt, private)
	if e != nil {
		t.Fatal(e)
	}
	material.Clear()
	if _, e := PreloadRuntimeMaterial(nil, private); e == nil {
		t.Fatal("missing protected salt")
	}
	if _, e := PreloadRuntimeMaterial(salt, nil); e == nil {
		t.Fatal("missing concrete key")
	}
	private[63] ^= 1
	if _, e := PreloadRuntimeMaterial(salt, private); e == nil {
		t.Fatal("inconsistent Ed25519 key")
	}
}
