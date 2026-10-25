package bundle

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"

	"filippo.io/age"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
)

// Vault is the profile's OS secret vault. Export key secrets live only here.
type Vault interface {
	Put(context.Context, string, []byte) error
	Get(context.Context, string) ([]byte, error)
	Delete(context.Context, string) error
}

// Identity is a profile's public pins: the pinned genesis, this device's
// signing key id and its machine.
type Identity struct {
	Genesis, Device, Machine string
}

type joinRecord struct {
	Version   int    `json:"version"`
	Genesis   string `json:"genesis"`
	Device    string `json:"device"`
	Machine   string `json:"machine"`
	DeviceAdd string `json:"device_add"`
}

// ProfileIdentity reads the installed public pins without any vault access.
// The device key is the genesis key unless a completed join names another.
func ProfileIdentity(dir string) (Identity, error) {
	genesis, machine, err := store.InstalledIdentity(dir)
	if err != nil {
		return Identity{}, ErrProfile
	}
	id := Identity{Genesis: genesis, Device: genesis, Machine: machine}
	b, err := store.ReadProfileRecord(dir, store.DeviceJoinName)
	if err != nil {
		if _, statErr := os.Lstat(filepath.Join(dir, store.DeviceJoinName)); errors.Is(statErr, os.ErrNotExist) {
			return id, nil
		}
		return Identity{}, ErrProfile
	}
	var j joinRecord
	if decodeFile(b, &j) != nil || j.Version != 1 || j.Genesis != genesis || j.Machine != machine || !record.IsKeyID(j.Device) {
		return Identity{}, ErrProfile
	}
	id.Device = j.Device
	return id, nil
}

func decodeFile(b []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return ErrProfile
	}
	return nil
}

func opaqueHandle() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", ErrExportKey
	}
	return hex.EncodeToString(b[:]), nil
}

// exportKey is the public record of this device's export key. The X25519
// secret is held only in the vault under Handle.
type exportKey struct {
	Version   int    `json:"version"`
	Genesis   string `json:"genesis"`
	Device    string `json:"device"`
	Machine   string `json:"machine"`
	Handle    string `json:"vault_handle"`
	Recipient string `json:"recipient"`
}

// Offer is what one device shows another so that it can be trusted as a
// transfer recipient. Code binds every field and is compared by the owner.
type Offer struct {
	Version   int    `json:"version"`
	Genesis   string `json:"genesis"`
	Device    string `json:"device"`
	Machine   string `json:"machine"`
	Recipient string `json:"recipient"`
	Code      string `json:"code"`
}

const exportKeyCodeDomain = "telara-memory export key v1"

func offerCode(o Offer) string {
	return Code(exportKeyCodeDomain, o.Genesis, o.Device, o.Machine, o.Recipient)
}

func readExportKey(dir string) (exportKey, bool, error) {
	var k exportKey
	b, err := store.ReadProfileRecord(dir, store.ExportKeyName)
	if err != nil {
		if _, statErr := os.Lstat(filepath.Join(dir, store.ExportKeyName)); errors.Is(statErr, os.ErrNotExist) {
			return k, false, nil
		}
		return k, false, ErrExportKey
	}
	if decodeFile(b, &k) != nil || k.Version != 1 || !record.IsKeyID(k.Genesis) || !record.IsKeyID(k.Device) || !record.IsUUIDv4(k.Machine) || !record.IsKeyID(k.Handle) {
		return k, false, ErrExportKey
	}
	if _, err = age.ParseX25519Recipient(k.Recipient); err != nil {
		return k, false, ErrExportKey
	}
	return k, true, nil
}

// EnsureExportKey returns this device's export key offer, creating the X25519
// key in the vault on first use.
func EnsureExportKey(ctx context.Context, dir string, v Vault, id Identity) (Offer, error) {
	k, ok, err := readExportKey(dir)
	if err != nil {
		return Offer{}, err
	}
	if !ok {
		identity, err := age.GenerateX25519Identity()
		if err != nil {
			return Offer{}, ErrExportKey
		}
		handle, err := opaqueHandle()
		if err != nil {
			return Offer{}, err
		}
		secret := []byte(identity.String())
		defer clear(secret)
		if v == nil || v.Put(ctx, handle, secret) != nil {
			return Offer{}, ErrExportKey
		}
		k = exportKey{1, id.Genesis, id.Device, id.Machine, handle, identity.Recipient().String()}
		b, err := json.Marshal(k)
		if err != nil || store.WriteProfileRecord(dir, store.ExportKeyName, b) != nil {
			_ = v.Delete(ctx, handle)
			return Offer{}, ErrExportKey
		}
	}
	if k.Genesis != id.Genesis || k.Device != id.Device || k.Machine != id.Machine {
		return Offer{}, ErrExportKey
	}
	o := Offer{Version: 1, Genesis: k.Genesis, Device: k.Device, Machine: k.Machine, Recipient: k.Recipient}
	o.Code = offerCode(o)
	return o, nil
}

// LoadExportIdentity returns this device's X25519 export identity.
func LoadExportIdentity(ctx context.Context, dir string, v Vault, id Identity) (*age.X25519Identity, error) {
	k, ok, err := readExportKey(dir)
	if err != nil || !ok || v == nil || k.Genesis != id.Genesis || k.Device != id.Device || k.Machine != id.Machine {
		return nil, ErrExportKey
	}
	secret, err := v.Get(ctx, k.Handle)
	defer clear(secret)
	if err != nil {
		return nil, ErrExportKey
	}
	identity, err := age.ParseX25519Identity(string(secret))
	if err != nil || identity.Recipient().String() != k.Recipient {
		return nil, ErrExportKey
	}
	return identity, nil
}

type recipientList struct {
	Version    int     `json:"version"`
	Recipients []Offer `json:"recipients"`
}

func readRecipients(dir string) (recipientList, error) {
	l := recipientList{Version: 1}
	b, err := store.ReadProfileRecord(dir, store.ExportRecipientsName)
	if err != nil {
		if _, statErr := os.Lstat(filepath.Join(dir, store.ExportRecipientsName)); errors.Is(statErr, os.ErrNotExist) {
			return l, nil
		}
		return l, ErrRecipient
	}
	if decodeFile(b, &l) != nil || l.Version != 1 {
		return l, ErrRecipient
	}
	return l, nil
}

// ParseOffer strictly decodes an offer and checks its code and fields.
func ParseOffer(r io.Reader) (Offer, error) {
	var o Offer
	b, err := io.ReadAll(io.LimitReader(r, 4097))
	if err != nil || len(b) > 4096 || decodeFile(b, &o) != nil {
		return o, ErrRecipient
	}
	if o.Version != 1 || !record.IsKeyID(o.Genesis) || !record.IsKeyID(o.Device) || !record.IsUUIDv4(o.Machine) || o.Code != offerCode(o) {
		return o, ErrRecipient
	}
	if _, err = age.ParseX25519Recipient(o.Recipient); err != nil {
		return o, ErrRecipient
	}
	return o, nil
}

// TrustRecipient records another device's export key after the owner typed
// the code that device displays. The device must be an active device of this
// genesis in the local keyring, bound to the offered machine.
func TrustRecipient(dir string, id Identity, keyring []store.SignedRecord, o Offer, typedCode string) error {
	if typedCode != o.Code {
		return ErrCode
	}
	if o.Genesis != id.Genesis {
		return ErrForeignGenesis
	}
	st, err := keyringOf(id.Genesis, keyring)
	if err != nil {
		return err
	}
	k := st.KeyFor(o.Device, record.RoleDevice, "")
	if k == nil || k.Status != sig.KeyActive || k.Genesis != id.Genesis || k.MachineID != o.Machine {
		return ErrNotEnrolled
	}
	l, err := readRecipients(dir)
	if err != nil {
		return err
	}
	kept := []Offer{}
	for _, r := range l.Recipients {
		if r.Device != o.Device {
			kept = append(kept, r)
		}
	}
	l.Recipients = append(kept, o)
	sort.Slice(l.Recipients, func(i, j int) bool { return l.Recipients[i].Device < l.Recipients[j].Device })
	if len(l.Recipients) > 64 {
		return ErrRecipient
	}
	b, err := json.Marshal(l)
	if err != nil || store.WriteProfileRecord(dir, store.ExportRecipientsName, b) != nil {
		return ErrRecipient
	}
	return nil
}

// Recipients resolves transfer targets to trusted export keys, rechecking at
// export time that each device is still active, unrevoked and on the same
// machine under the current keyring.
func Recipients(dir string, id Identity, keyring []store.SignedRecord, devices []string) ([]string, error) {
	if len(devices) == 0 {
		return nil, ErrRecipient
	}
	l, err := readRecipients(dir)
	if err != nil {
		return nil, err
	}
	st, err := keyringOf(id.Genesis, keyring)
	if err != nil {
		return nil, err
	}
	var out []string
	seen := map[string]bool{}
	for _, device := range devices {
		if seen[device] {
			return nil, ErrRecipient
		}
		seen[device] = true
		var found *Offer
		for i := range l.Recipients {
			if l.Recipients[i].Device == device {
				found = &l.Recipients[i]
			}
		}
		if found == nil || found.Genesis != id.Genesis || found.Code != offerCode(*found) {
			return nil, ErrRecipient
		}
		k := st.KeyFor(device, record.RoleDevice, "")
		if k == nil || k.Status != sig.KeyActive || k.Genesis != id.Genesis || k.MachineID != found.Machine {
			return nil, ErrNotEnrolled
		}
		out = append(out, found.Recipient)
	}
	return out, nil
}
