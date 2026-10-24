package disclosure

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/daemon"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
)

// SecretVault is supplied by the trusted installer, backed by the OS keystore.
// Put must refuse an existing handle and durably commit before returning. Get
// returns an owned copy. No environment, wire input or plaintext key file is a
// fallback. This seam deliberately does not install an OS-specific vault.
type SecretVault interface {
	Put(context.Context, string, []byte) error
	Get(context.Context, string) ([]byte, error)
	Delete(context.Context, string) error
}

// PeerAuthority authenticates the actual peer executable/installation and drains
// capture signals. Hello.Client/Cwd/Ancestry are hints, never authorization. A
// missing authority denies every request; an owner-only file is not peer proof.
type PeerAuthority interface {
	VerifyAndDrain(context.Context, ipc.Hello, string) error
}
type InstalledProvider struct {
	Dir   string
	Vault SecretVault
	Peers PeerAuthority
}
type InstalledRuntime struct {
	Config      Config
	Material    RuntimeMaterial
	Credentials *InstalledCredentials
}
type InstalledCredentials struct {
	vault    SecretVault
	peers    PeerAuthority
	manifest installedManifest
}
type installedManifest struct {
	Version     int    `json:"version"`
	Owner       string `json:"owner"`
	Machine     string `json:"machine"`
	Credential  string `json:"credential"`
	VaultHandle string `json:"vault_handle"`
}

func installedFailure() error { return errors.New("runtime_authority_unavailable") }
func opaqueID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", installedFailure()
	}
	defer clear(b[:])
	return hex.EncodeToString(b[:]), nil
}

// BootstrapInstalled is an explicit trusted installer action. It initializes a
// fresh profile only and uses exactly the owner's supplied grants. Opening the
// daemon never invokes it or manufactures a registration/grant.
func BootstrapInstalled(ctx context.Context, dir, name string, grant Grant, writes TaskWriteGrant, vault SecretVault) error {
	if vault == nil || !filepath.IsAbs(dir) || ipc.ValidateDir(dir, true) != nil {
		return installedFailure()
	}
	for _, name := range []string{"memory.sqlite", "installed-authority.json"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			return installedFailure()
		}
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return installedFailure()
	}
	defer clear(key)
	rawID, err := opaqueID()
	if err != nil {
		return err
	}
	rawBytes, _ := hex.DecodeString(rawID)
	rawBytes[6] = rawBytes[6]&15 | 64
	rawBytes[8] = rawBytes[8]&63 | 128
	rawID = hex.EncodeToString(rawBytes)
	clear(rawBytes)
	machine := rawID[:8] + "-" + rawID[8:12] + "-" + rawID[12:16] + "-" + rawID[16:20] + "-" + rawID[20:]
	owner := sig.KeyID(pub)
	st, err := store.Open(ctx, store.Options{Dir: dir, PinnedGenesisID: owner, LocalMachineID: machine})
	if err != nil {
		return installedFailure()
	}
	defer st.Close()
	op, err := sig.BuildKeyOp(record.KeyOpBody{Op: record.OpGenesis, Subject: sig.KeyRefOf(pub, record.RoleDevice, machine), Genesis: owner}, pub, machine, 1, key)
	if err != nil {
		return installedFailure()
	}
	if _, err = st.Append(ctx, store.SignedRecord{HeaderJCS: op.Rec.HeaderJCS, BodyJCS: op.Rec.BodyJCS, Sigs: op.Sigs, AdvisoryID: op.Rec.ID}); err != nil {
		return installedFailure()
	}
	// Retired salt parameter is compatibility-only; it is never a seal input.
	material, err := PreloadRuntimeMaterial(make([]byte, 32), key)
	if err != nil {
		return installedFailure()
	}
	defer material.Clear()
	svc, err := New(ctx, st, Config{OwnerGenesis: owner, MachineID: machine}, material)
	if err != nil {
		return installedFailure()
	}
	defer svc.Close()
	admin, err := svc.Administration(ctx)
	if err != nil {
		return installedFailure()
	}
	adminID, err := opaqueID()
	if err != nil {
		return err
	}
	client, err := admin.Register(ctx, RegisterClient{AdminOpID: adminID, ClientName: name, ReadGrant: grant, TaskWrites: writes})
	if err != nil {
		return installedFailure()
	}
	token, err := client.Secret.Take()
	if err != nil {
		return installedFailure()
	}
	defer clear(token)
	handle, err := opaqueID()
	if err != nil {
		return err
	}
	secret := append(append([]byte{}, key...), token...)
	defer clear(secret)
	if vault.Put(ctx, handle, secret) != nil {
		return installedFailure()
	}
	manifest := installedManifest{1, owner, machine, client.CredentialID, handle}
	b, err := json.Marshal(manifest)
	if err != nil {
		return installedFailure()
	}
	if store.WriteInstalledRecord(dir, b) != nil {
		return installedFailure()
	}
	return nil
}
func (p InstalledProvider) Load(ctx context.Context) (InstalledRuntime, error) {
	var out InstalledRuntime
	if p.Vault == nil || p.Peers == nil || !filepath.IsAbs(p.Dir) || ipc.ValidateDir(p.Dir, false) != nil {
		return out, installedFailure()
	}
	b, err := store.ReadInstalledRecord(p.Dir)
	if err != nil {
		return out, installedFailure()
	}
	var m installedManifest
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if dec.Decode(&m) != nil || dec.Decode(new(any)) != io.EOF || m.Version != 1 || !record.IsKeyID(m.Owner) || !record.IsUUIDv4(m.Machine) || !record.IsUUIDv4(m.Credential) || !record.IsKeyID(m.VaultHandle) {
		return out, installedFailure()
	}
	secret, err := p.Vault.Get(ctx, m.VaultHandle)
	defer clear(secret)
	if err != nil || len(secret) != 96 {
		return out, installedFailure()
	}
	private := ed25519.PrivateKey(secret[:64])
	if sig.KeyID(private.Public().(ed25519.PublicKey)) != m.Owner {
		return out, installedFailure()
	}
	material, err := PreloadRuntimeMaterial(make([]byte, 32), private)
	if err != nil {
		return out, installedFailure()
	}
	return InstalledRuntime{Config{OwnerGenesis: m.Owner, MachineID: m.Machine}, material, &InstalledCredentials{p.Vault, p.Peers, m}}, nil
}
func (p *InstalledCredentials) Proof(ctx context.Context, h ipc.Hello) (CredentialProof, error) {
	if p == nil || p.vault == nil || p.peers == nil || daemon.AuthenticatedPeerPID(ctx) != h.PID || h.PID <= 0 {
		return CredentialProof{}, installedFailure()
	}
	if p.peers.VerifyAndDrain(ctx, h, p.manifest.Credential) != nil {
		return CredentialProof{}, installedFailure()
	}
	secret, err := p.vault.Get(ctx, p.manifest.VaultHandle)
	defer clear(secret)
	if err != nil || len(secret) != 96 {
		return CredentialProof{}, installedFailure()
	}
	return CredentialProof{CredentialID: p.manifest.Credential, Token: append([]byte(nil), secret[64:]...)}, nil
}
