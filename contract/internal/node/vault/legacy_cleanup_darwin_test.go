//go:build darwin && cgo

package vault

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// This focused refusal test requires no image execution or native Keychain.
// The absent install and custody-location records deliberately prove that
// runtime-only legacy state is recognized before reaching either subsystem.
func TestHistoricalRuntimeOnlyUninstallRefusesBeforeCustodyOrMetadataMutation(t *testing.T) {
	m := fixtureProfileHandoff(t)
	runtime := custodyHandoff{1, m.Source, m.Target, m.Entries[0].Reference.Handle, m.Entries[0].Source.Keychain, "prepared", false}
	if err := writeHandoff(runtime); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadDir(m.Source.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	marker, err := privateRead(filepath.Join(m.Source.DataDir, handoffFile))
	if err != nil {
		t.Fatal(err)
	}
	v := New()
	for i := 0; i < 2; i++ {
		if err := v.PrepareProfileUninstall(context.Background(), m.Source); !errors.Is(err, ErrLegacyCustody) {
			t.Fatalf("expected maintenance refusal, got %v", err)
		}
		if v.keychainPath != "" || v.keychain != 0 {
			t.Fatal("legacy preflight selected native custody")
		}
		got, err := privateRead(filepath.Join(m.Source.DataDir, handoffFile))
		if err != nil || !bytes.Equal(got, marker) {
			t.Fatal("legacy preflight changed marker", err)
		}
		after, err := os.ReadDir(m.Source.DataDir)
		if err != nil || !reflect.DeepEqual(entryNames(before), entryNames(after)) {
			t.Fatal("legacy preflight created or removed metadata", err)
		}
	}
}

func entryNames(entries []os.DirEntry) []string {
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func TestHistoricalRuntimeOnlyUninstallPreservesMalformedMarker(t *testing.T) {
	dir := profileTestDir(t)
	path := filepath.Join(dir, handoffFile)
	marker := []byte(`{"version":1,"source":{},"unknown":true}`)
	if err := os.WriteFile(path, marker, 0600); err != nil {
		t.Fatal(err)
	}
	m := fixtureProfileHandoff(t)
	m.Source.DataDir = dir
	if err := New().PrepareProfileUninstall(context.Background(), m.Source); err == nil {
		t.Fatal("malformed historical state admitted")
	}
	got, err := privateRead(path)
	if err != nil || !bytes.Equal(got, marker) {
		t.Fatal("malformed state was removed or replaced", err)
	}
}

func TestNativeEnumerationOpcodeRejectedAndOwnedItemUnchanged(t *testing.T) {
	v, keychain := isolatedVault(t)
	ctx := context.Background()
	handle := "0badc0de0badc0de0badc0de0badc0de"
	secret := []byte("owned native enumeration refusal fixture")
	if err := v.Put(ctx, handle, secret); err != nil {
		t.Fatal(err)
	}
	defer v.Delete(ctx, handle)
	// Opcode11 previously searched all service namespaces for this account.
	// Supplying a real populated isolated Keychain makes the old implementation
	// observably return a successful enumeration response, which must now fail.
	raw := make([]byte, 35+len(keychain)+len(service))
	raw[0] = 11
	copy(raw[1:33], handle)
	binary.BigEndian.PutUint16(raw[33:35], uint16(len(keychain)))
	copy(raw[35:], keychain)
	copy(raw[35+len(keychain):], service)
	var out bytes.Buffer
	if !RunHelper([]string{helperArg}, bytes.NewReader(raw), &out) || !bytes.Equal(out.Bytes(), []byte{3}) {
		t.Fatal("removed enumeration operation remained reachable")
	}
	got, err := v.Get(ctx, handle)
	if err != nil || !bytes.Equal(got, secret) {
		clear(got)
		t.Fatal("enumeration refusal changed owned credential", err)
	}
	clear(got)
}
