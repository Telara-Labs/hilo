package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/Telara-Labs/hilo/contract/internal/node/install"
	"github.com/Telara-Labs/hilo/contract/internal/node/ipc"
	"github.com/Telara-Labs/hilo/contract/internal/node/store"
)

func TestCreatorRecordMaximumSerializationRoundTrip(t *testing.T) {
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	data := filepath.Join(root, "profile")
	if e = ipc.ValidateDir(data, true); e != nil {
		t.Fatal(e)
	}
	r := install.Record{Dir: filepath.Join(root, "install"), DataDir: data, SHA256: strings.Repeat("a", 64)}
	name := "telara-memory"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	r.Executable = filepath.Join(r.Dir, "bin", r.SHA256, name)
	p := pendingProfile{Version: 1, Phase: "provisioning", Handle: strings.Repeat("b", 32), Creator: &r}
	raw, _ := json.Marshal(p)
	r.Version = strings.Repeat("v", maxAuthorityRecord-len(raw))
	raw, _ = json.Marshal(p)
	if len(raw) != maxAuthorityRecord {
		t.Fatal(len(raw))
	}
	if e = writePending(data, p); e != nil {
		t.Fatal(e)
	}
	got, e := readPending(data)
	if e != nil || !reflect.DeepEqual(got, p) {
		t.Fatal("maximum creator record failed", e)
	}
	r.Version += "x"
	if e = writePending(data, p); e == nil {
		t.Fatal("oversized record published")
	}
	after, e := readAuthorityRecord(data)
	if e != nil || !bytes.Equal(raw, after) {
		t.Fatal("oversized refusal changed record", e)
	}
}

func TestInvalidManifestProvisioningDeletionDispatch(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("native Windows bootstrap has separate fixture")
	}
	for _, content := range []string{"", "{", `{"version":1}`, `null`} {
		t.Run(content, func(t *testing.T) {
			root, e := filepath.EvalSymlinks(t.TempDir())
			if e != nil {
				t.Fatal(e)
			}
			data := filepath.Join(root, "data")
			dir := filepath.Join(root, "install")
			r := install.Record{Dir: dir, DataDir: data, SHA256: strings.Repeat("a", 64)}
			r.Executable = filepath.Join(dir, "bin", r.SHA256, "telara-memory")
			native := &deletionTestCustody{}
			if e = provisionAuthority(context.Background(), data, native, nil); e != nil {
				t.Fatal(e)
			}
			p, e := readPending(data)
			if e != nil {
				t.Fatal(e)
			}
			p.Phase = "provisioning"
			p.Creator = &r
			if e = writePending(data, p); e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(filepath.Join(data, "installed-authority.json"), []byte(content), 0600); e != nil {
				t.Fatal(e)
			}
			staging := filepath.Join(data, "custody-upgrade.json")
			if e = os.WriteFile(staging, []byte("{"), 0600); e != nil {
				t.Fatal(e)
			}
			if e = deleteNeverAdmittedAuthority(context.Background(), data, installedDeletionVault{native, r}); e == nil {
				t.Fatal("unknown transfer cleaned")
			}
			if e = os.Remove(staging); e != nil {
				t.Fatal(e)
			}
			if e = deleteNeverAdmittedAuthority(context.Background(), data, installedDeletionVault{native, r}); e != nil {
				t.Fatal(e)
			}
			if native.created != 1 || native.installed != 0 || len(native.values) != 0 {
				t.Fatal("wrong deletion path")
			}
		})
	}
}

func TestAtomicInstalledManifestPublication(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("store native privacy acceptance separate")
	}
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	// A process interruption before rename cannot create a partial final manifest.
	if e = os.WriteFile(filepath.Join(root, ".installed-authority-interrupted"), []byte("{"), 0600); e != nil {
		t.Fatal(e)
	}
	want := []byte(`{"version":1,"opaque":"public pins only"}`)
	if e = store.WriteInstalledRecord(root, want); e != nil {
		t.Fatal(e)
	}
	got, e := store.ReadInstalledRecord(root)
	if e != nil || !bytes.Equal(want, got) {
		t.Fatal(e)
	}
	if e = store.WriteInstalledRecord(root, []byte("replacement")); e == nil {
		t.Fatal("existing authority replaced")
	}
	got, e = store.ReadInstalledRecord(root)
	if e != nil || !bytes.Equal(want, got) {
		t.Fatal("existing authority changed", e)
	}
}

func TestLongPlannedInstallerCreatorRoundTrip(t *testing.T) {
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	data := filepath.Join(root, "profile")
	if e = ipc.ValidateDir(data, true); e != nil {
		t.Fatal(e)
	}
	dir := filepath.Join(root, strings.Repeat("a", 200), strings.Repeat("b", 200))
	r, e := install.PlannedRecord(install.Config{Dir: dir, Home: root, SHA256: strings.Repeat("c", 64), Version: strings.Repeat("v", 128), DataDir: data, RunDir: filepath.Join(root, "run")})
	if e != nil {
		t.Fatal(e)
	}
	p := pendingProfile{Version: 1, Phase: "provisioning", Handle: strings.Repeat("d", 32), Creator: &r}
	raw, _ := json.Marshal(p)
	if len(raw) <= 1024 {
		t.Fatal("fixture does not cover prior reader bound")
	}
	if e = writePending(data, p); e != nil {
		t.Fatal(e)
	}
	got, e := readPending(data)
	if e != nil || !reflect.DeepEqual(got, p) {
		t.Fatal("valid long installer creator refused", e)
	}
}
