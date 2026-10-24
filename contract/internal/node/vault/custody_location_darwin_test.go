//go:build darwin && cgo

package vault

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCustodyLocationPinsBeforePutAndRefusesLostStore(t *testing.T) {
	data, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(data, 0700); e != nil {
		t.Fatal(e)
	}
	k1 := filepath.Join(data, "k1.keychain")
	k2 := filepath.Join(data, "k2.keychain")
	// No native operation is performed in this filesystem unit case.
	for _, path := range []string{k1, k2} {
		if e = os.WriteFile(path, []byte("unit custody location sentinel"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	first := &Vault{keychainPath: k1}
	if e = first.bindCustody(context.Background(), data, true); e != nil {
		t.Fatal(e)
	}
	raw, e := privateRead(filepath.Join(data, custodyLocationFile))
	if e != nil {
		t.Fatal(e)
	}
	var m custodyLocation
	if json.Unmarshal(raw, &m) != nil || m.Keychain != k1 {
		t.Fatal("location not durable before native Put")
	}
	// Represents another process whose selected default has changed to K2.
	next := &Vault{keychainPath: k2}
	if e = next.bindCustody(context.Background(), data, false); e != nil || next.keychainPath != k1 {
		t.Fatal("default redirected custody", e)
	}
	if e = os.Remove(k1); e != nil {
		t.Fatal(e)
	}
	if e = next.bindCustody(context.Background(), data, false); e == nil {
		t.Fatal("unavailable recorded store replaced by different default")
	}
	after, _ := os.ReadFile(filepath.Join(data, custodyLocationFile))
	if string(after) != string(raw) {
		t.Fatal("lost-store refusal destroyed custody evidence")
	}
	if e = os.Remove(filepath.Join(data, custodyLocationFile)); e != nil {
		t.Fatal(e)
	}
	if e = next.bindCustody(context.Background(), data, false); e == nil {
		t.Fatal("unrecorded location accepted for cleanup")
	}
}

func TestNativeCustodyLocationIgnoresChangedSelection(t *testing.T) {
	first, k1 := isolatedVault(t)
	second, _ := isolatedVault(t)
	// The profile data directory is the node's own private directory, never the
	// keychain's folder.
	data, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(data, 0700); e != nil {
		t.Fatal(e)
	}
	if e := first.bindCustody(context.Background(), data, true); e != nil {
		t.Fatal(e)
	}
	// The caller has K2 selected, but profile custody must continue using K1.
	if e := second.bindCustody(context.Background(), data, false); e != nil {
		t.Fatal(e)
	}
	if second.keychainPath != k1 {
		t.Fatal("wrong recorded location")
	}
	h := "d123456789abcdef0123456789abcdef"
	if e := first.Put(context.Background(), h, []byte("isolated native location fixture")); e != nil {
		t.Fatal(e)
	}
	if e := second.Delete(context.Background(), h); e != nil {
		t.Fatal(e)
	}
	if _, e := first.Get(context.Background(), h); e != ErrNotFound {
		t.Fatal("credential retained in K1", e)
	}
}

func TestCustodyLocationRejectsInvalidRecordsWithoutMutation(t *testing.T) {
	data, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(data, 0700); e != nil {
		t.Fatal(e)
	}
	for _, raw := range []string{"{", `{"version":2,"keychain":"/missing"}`, `{"version":1,"keychain":"relative"}`, `{"version":1,"keychain":"/missing","extra":true}`} {
		path := filepath.Join(data, custodyLocationFile)
		if e = os.WriteFile(path, []byte(raw), 0600); e != nil {
			t.Fatal(e)
		}
		if e = New().bindCustody(context.Background(), data, false); e == nil {
			t.Fatal("invalid location accepted", raw)
		}
		after, _ := os.ReadFile(path)
		if string(after) != raw {
			t.Fatal("invalid custody evidence changed")
		}
	}
	if e = os.Remove(filepath.Join(data, custodyLocationFile)); e != nil {
		t.Fatal(e)
	}
	v := &Vault{keychainPath: "relative"}
	if e = v.bindCustody(context.Background(), data, true); e == nil {
		t.Fatal("invalid selection persisted")
	}
	if _, e = os.Lstat(filepath.Join(data, custodyLocationFile)); !os.IsNotExist(e) {
		t.Fatal("invalid selection mutated custody", e)
	}
}
