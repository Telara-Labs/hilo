//go:build darwin && cgo

package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/custodyguard"
)

// These filesystem cases isolate journal and binding rules. The unchanged real
// native-slot and two-upgrade fixtures remain the behavioral acceptance gates.
func readyRetryProfile(t *testing.T) profileHandoff {
	t.Helper()
	m := fixtureProfileHandoff(t)
	manifest, err := json.Marshal(map[string]any{
		"version": 1, "owner": m.Entries[0].Reference.Handle,
		"machine":      "00000000-0000-4000-8000-000000000001",
		"vault_handle": m.Entries[0].Reference.Handle,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(m.Source.DataDir, "installed-authority.json"), manifest, 0600); err != nil {
		t.Fatal(err)
	}
	refs, generation, err := inventory(m.Source.DataDir)
	if err != nil || len(refs) != 1 || refs[0] != m.Entries[0].Reference {
		t.Fatal("retry fixture inventory", refs, err)
	}
	m.Generation, m.Phase, m.Entries[0].Stage = generation, "ready", "copied"
	return m
}

func TestProfileReadyRetryPersistsPreparingBeforeEntryMutation(t *testing.T) {
	m := readyRetryProfile(t)
	if err := writeProfileHandoff(m); err != nil {
		t.Fatal(err)
	}
	v := New()
	got, err := v.prepareProfileInventory(context.Background(), m.Source, m.Target)
	if err != nil {
		t.Fatal(err)
	}
	want := m
	want.Phase = "preparing"
	if !reflect.DeepEqual(got, want) {
		t.Fatal("retry changed ownership or inventory", got)
	}
	durable, err := readProfileHandoff(m.Source.DataDir)
	if err != nil || !reflect.DeepEqual(durable, want) {
		t.Fatal("preparing transition not durable", durable, err)
	}
	if err := verifyPreparedProfile(context.Background(), v, durable); !errors.Is(err, ErrUnavailable) {
		t.Fatal("publication accepted incomplete retry", err)
	}
	// Simulate interruption after the pre-create checkpoint. A fresh reader
	// must retain that checkpoint and its exact committed creator identities.
	durable.Entries[0].Stage = "creating"
	if err := writeProfileHandoff(durable); err != nil {
		t.Fatal("retry cannot persist pre-create checkpoint", err)
	}
	resumed, err := New().prepareProfileInventory(context.Background(), m.Source, m.Target)
	if err != nil || !reflect.DeepEqual(resumed, durable) {
		t.Fatal("interrupted retry did not preserve creation evidence", resumed, err)
	}
}

func TestProfileReadyRetryRefusesChangedIdentityAndRetirement(t *testing.T) {
	for _, name := range []string{"source", "target", "generation", "reference", "retiring", "retirement-pending", "retired"} {
		t.Run(name, func(t *testing.T) {
			m := readyRetryProfile(t)
			source, target := m.Source, m.Target
			switch name {
			case "source":
				m.Source.Version = "different source receipt"
			case "target":
				target = m.Source.SHA256
			case "generation":
				m.Generation = m.Source.SHA256
			case "reference":
				other := "abcdef0123456789abcdef0123456789"
				m.Entries[0].Reference.Handle = other
				m.Entries[0].Source.Handle, m.Entries[0].Target.Handle = other, other
			case "retiring":
				m.Phase = "retiring"
			case "retirement-pending":
				m.Entries[0].RetirementPending = true
			case "retired":
				m.Entries[0].RetirementPending, m.Entries[0].Retired = true, true
			}
			if err := writeProfileHandoff(m); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(source.DataDir, custodyguard.ProfileJournal)
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := New().prepareProfileInventory(context.Background(), source, target); !errors.Is(err, ErrUnavailable) {
				t.Fatal("unsafe retry accepted", err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("refusal changed durable evidence", err)
			}
		})
	}
}

func TestCustodyBindingPinsExactProfileForRetiredCleanup(t *testing.T) {
	m := fixtureProfileHandoff(t)
	data, keychain := m.Source.DataDir, m.Entries[0].Source.Keychain
	if err := os.WriteFile(keychain, []byte("filesystem-only keychain sentinel"), 0600); err != nil {
		t.Fatal(err)
	}
	v := &Vault{keychainPath: keychain}
	if err := v.bindCustody(context.Background(), data, true); err != nil || v.profile != data {
		t.Fatal("validated custody did not bind profile", v.profile, err)
	}
	r := m.Entries[0].Source
	r.Phase = "deleted"
	if err := writeCreator(data, nil, r); err != nil {
		t.Fatal(err)
	}
	if err := v.deleteProfile(context.Background(), r.Handle); err != nil {
		t.Fatal("cleanup did not use validated absolute profile", err)
	}
	if _, err := os.Stat(filepath.Join(data, "custody-creator-"+r.Handle+".lock")); err != nil {
		t.Fatal("cleanup lock missing from bound profile", err)
	}
}

func TestCustodyBindingRefusesProfileRedirectionBeforeMutation(t *testing.T) {
	first, second := profileTestDir(t), profileTestDir(t)
	keychain := filepath.Join(first, "keychain")
	if err := os.WriteFile(keychain, []byte("filesystem-only keychain sentinel"), 0600); err != nil {
		t.Fatal(err)
	}
	v := &Vault{keychainPath: keychain}
	if err := v.bindCustody(context.Background(), first, true); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(first, custodyLocationFile))
	if err != nil {
		t.Fatal(err)
	}
	for _, create := range []bool{false, true} {
		if err := v.bindCustody(context.Background(), second, create); !errors.Is(err, ErrUnavailable) {
			t.Fatal("conflicting profile accepted", create, err)
		}
		if v.profile != first || v.keychainPath != keychain {
			t.Fatal("refusal changed in-memory binding")
		}
		if entries, err := os.ReadDir(second); err != nil || len(entries) != 0 {
			t.Fatal("refusal created metadata in conflicting profile", entries, err)
		}
	}
	after, err := os.ReadFile(filepath.Join(first, custodyLocationFile))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("refusal changed original location record", err)
	}
}

func TestCustodyBindingPreservesExactPrivatePathGate(t *testing.T) {
	data := profileTestDir(t)
	keychain := filepath.Join(data, "keychain")
	if err := os.WriteFile(keychain, []byte("filesystem-only keychain sentinel"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(profileTestDir(t), "profile-link")
	if err := os.Symlink(data, link); err != nil {
		t.Fatal(err)
	}
	unsafe := profileTestDir(t)
	if err := os.Chmod(unsafe, 0755); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"", ".", "relative", data + "/.", link, unsafe} {
		v := &Vault{keychainPath: keychain}
		if err := v.bindCustody(context.Background(), path, true); !errors.Is(err, ErrUnavailable) {
			t.Fatal("unsafe profile accepted", path, err)
		}
		if v.profile != "" || v.keychainPath != keychain {
			t.Fatal("unsafe profile changed binding", path)
		}
	}
	if _, err := os.Lstat(filepath.Join(data, custodyLocationFile)); !os.IsNotExist(err) {
		t.Fatal("normalized or symlink path created metadata", err)
	}
}
