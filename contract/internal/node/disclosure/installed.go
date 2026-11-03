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

	"github.com/Telara-Labs/hilo/contract/internal/node/daemon"
	"github.com/Telara-Labs/hilo/contract/internal/node/ipc"
	"github.com/Telara-Labs/hilo/contract/internal/node/store"
	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/sig"
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
	dir      string
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
	if err := freshProfile(dir, vault); err != nil {
		return err
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return installedFailure()
	}
	defer clear(key)
	machine, err := NewMachineID()
	if err != nil {
		return err
	}
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
	return provisionInstalled(ctx, st, dir, owner, machine, key, name, grant, writes, vault)
}

// deviceJoin is the public record of a device enrolled into an existing
// genesis by a co-signed device_add. Its device key differs from the genesis.
type deviceJoin struct {
	Version   int    `json:"version"`
	Genesis   string `json:"genesis"`
	Device    string `json:"device"`
	Machine   string `json:"machine"`
	DeviceAdd string `json:"device_add"`
}

// BootstrapJoined provisions a fresh profile for a device that joins the
// existing genesis named by keyring. keyring must contain the authorized,
// co-signed device_add for key on machine; the store and the disclosure
// engine refuse a key that the keyring does not make active.
func BootstrapJoined(ctx context.Context, dir, name string, grant Grant, writes TaskWriteGrant, vault SecretVault, key ed25519.PrivateKey, machine, genesis, deviceAdd string, keyring []store.SignedRecord) error {
	if err := freshProfile(dir, vault); err != nil {
		return err
	}
	if len(key) != ed25519.PrivateKeySize || !record.IsUUIDv4(machine) || !record.IsKeyID(genesis) || !record.IsHex64(deviceAdd) || len(keyring) < 2 {
		return installedFailure()
	}
	device := sig.KeyID(key.Public().(ed25519.PublicKey))
	if device == genesis {
		return installedFailure()
	}
	st, err := store.Open(ctx, store.Options{Dir: dir, PinnedGenesisID: genesis, LocalMachineID: machine})
	if err != nil {
		return installedFailure()
	}
	defer st.Close()
	for _, r := range keyring {
		if _, err = st.Append(ctx, r); err != nil {
			return installedFailure()
		}
	}
	b, err := json.Marshal(deviceJoin{1, genesis, device, machine, deviceAdd})
	if err != nil || store.WriteProfileRecord(dir, store.DeviceJoinName, b) != nil {
		return installedFailure()
	}
	return provisionInstalled(ctx, st, dir, genesis, machine, key, name, grant, writes, vault)
}

func freshProfile(dir string, vault SecretVault) error {
	if vault == nil || !filepath.IsAbs(dir) || ipc.ValidateDir(dir, true) != nil {
		return installedFailure()
	}
	for _, name := range []string{"memory.sqlite", "installed-authority.json", store.DeviceJoinName} {
		if _, err := os.Lstat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			return installedFailure()
		}
	}
	return nil
}

// NewMachineID returns a fresh random UUIDv4 machine id.
func NewMachineID() (string, error) {
	rawID, err := opaqueID()
	if err != nil {
		return "", err
	}
	rawBytes, _ := hex.DecodeString(rawID)
	rawBytes[6] = rawBytes[6]&15 | 64
	rawBytes[8] = rawBytes[8]&63 | 128
	rawID = hex.EncodeToString(rawBytes)
	clear(rawBytes)
	return rawID[:8] + "-" + rawID[8:12] + "-" + rawID[12:16] + "-" + rawID[16:20] + "-" + rawID[20:], nil
}

func provisionInstalled(ctx context.Context, st *store.Store, dir, owner, machine string, key ed25519.PrivateKey, name string, grant Grant, writes TaskWriteGrant, vault SecretVault) error {
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

// InstalledDeviceKey returns the installed profile's pinned genesis, machine
// and a copy of its device signing key, which the caller must clear.
func InstalledDeviceKey(ctx context.Context, dir string, vault SecretVault) (genesis, machine string, key ed25519.PrivateKey, err error) {
	m, key, err := loadInstalledKey(ctx, dir, vault)
	if err != nil {
		return "", "", nil, err
	}
	return m.Owner, m.Machine, key, nil
}

func readManifest(dir string) (installedManifest, error) {
	var m installedManifest
	b, err := store.ReadInstalledRecord(dir)
	if err != nil {
		return m, installedFailure()
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if dec.Decode(&m) != nil || dec.Decode(new(any)) != io.EOF || m.Version != 1 || !record.IsKeyID(m.Owner) || !record.IsUUIDv4(m.Machine) || !record.IsUUIDv4(m.Credential) || !record.IsKeyID(m.VaultHandle) {
		return installedManifest{}, installedFailure()
	}
	return m, nil
}

// loadInstalledKey checks that the vault key is the genesis key or the device
// key recorded by a completed join of this genesis and machine.
func loadInstalledKey(ctx context.Context, dir string, vault SecretVault) (installedManifest, ed25519.PrivateKey, error) {
	if vault == nil || !filepath.IsAbs(dir) || ipc.ValidateDir(dir, false) != nil {
		return installedManifest{}, nil, installedFailure()
	}
	m, err := readManifest(dir)
	if err != nil {
		return m, nil, err
	}
	secret, err := vault.Get(ctx, m.VaultHandle)
	defer clear(secret)
	if err != nil || len(secret) != 96 {
		return installedManifest{}, nil, installedFailure()
	}
	key := ed25519.PrivateKey(append([]byte(nil), secret[:64]...))
	if !bytes.Equal(key, ed25519.NewKeyFromSeed(key[:32])) {
		clear(key)
		return installedManifest{}, nil, installedFailure()
	}
	if id := sig.KeyID(key.Public().(ed25519.PublicKey)); id != m.Owner {
		b, err := store.ReadProfileRecord(dir, store.DeviceJoinName)
		var j deviceJoin
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.DisallowUnknownFields()
		if err != nil || dec.Decode(&j) != nil || dec.Decode(new(any)) != io.EOF || j.Version != 1 || j.Genesis != m.Owner || j.Device != id || j.Machine != m.Machine || !record.IsHex64(j.DeviceAdd) {
			clear(key)
			return installedManifest{}, nil, installedFailure()
		}
	}
	return m, key, nil
}

func (p InstalledProvider) Load(ctx context.Context) (InstalledRuntime, error) {
	var out InstalledRuntime
	if p.Vault == nil || p.Peers == nil {
		return out, installedFailure()
	}
	m, private, err := loadInstalledKey(ctx, p.Dir, p.Vault)
	if err != nil {
		return out, err
	}
	defer clear(private)
	material, err := PreloadRuntimeMaterial(make([]byte, 32), private)
	if err != nil {
		return out, installedFailure()
	}
	return InstalledRuntime{Config{OwnerGenesis: m.Owner, MachineID: m.Machine}, material, &InstalledCredentials{dir: p.Dir, vault: p.Vault, peers: p.Peers, manifest: m}}, nil
}
func (p *InstalledCredentials) Proof(ctx context.Context, h ipc.Hello) (CredentialProof, error) {
	if p == nil || p.vault == nil || p.peers == nil || daemon.AuthenticatedPeerPID(ctx) != h.PID || h.PID <= 0 {
		return CredentialProof{}, installedFailure()
	}
	if p.peers.VerifyAndDrain(ctx, h, p.manifest.Credential) != nil {
		return CredentialProof{}, installedFailure()
	}
	if h.RepositoryContext != "" {
		return repositoryContextProof(ctx, p.dir, h.RepositoryContext, p.vault)
	}
	secret, err := p.vault.Get(ctx, p.manifest.VaultHandle)
	defer clear(secret)
	if err != nil || len(secret) != 96 {
		return CredentialProof{}, installedFailure()
	}
	return CredentialProof{CredentialID: p.manifest.Credential, Token: append([]byte(nil), secret[64:]...)}, nil
}
