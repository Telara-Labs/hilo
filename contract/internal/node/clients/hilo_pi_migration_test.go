package clients

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func hiloLegacyPi(t *testing.T) (Options, Location, []byte) {
	t.Helper()
	o := options(t, Pi)
	l, err := Locations(o)
	if err != nil {
		t.Fatal(err)
	}
	old := []byte(strings.Replace(piExtension(o), `pi.registerMcpServer("hilo",`, `pi.registerMcpServer("telara-memory",`, 1))
	if bytes.Equal(old, []byte(piExtension(o))) {
		t.Fatal("legacy adapter fixture did not retain old registration")
	}
	put(t, filepath.Join(filepath.Dir(l.Extension), legacyExtensionName), old)
	receipt, err := json.Marshal(piReceipt{Version: 1, Digest: digest(old)})
	if err != nil {
		t.Fatal(err)
	}
	put(t, filepath.Join(filepath.Dir(l.Extension), legacyReceiptName), receipt)
	return o, l, old
}

func hiloOnlyCurrentPi(t *testing.T, l Location, old []byte) string {
	t.Helper()
	dir := filepath.Dir(l.Extension)
	if filepath.Base(l.Extension) != "hilo.js" {
		t.Fatal("current extension has wrong name")
	}
	for _, name := range []string{legacyExtensionName, legacyReceiptName} {
		if _, err := os.Lstat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatal("legacy registration remains active", err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	active := 0
	parked := ""
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".js") {
			active++
			if entry.Name() != extensionName {
				t.Fatal("extra event adapter remains active")
			}
		}
		if strings.HasPrefix(entry.Name(), ".hilo-remove-") {
			b, err := os.ReadFile(filepath.Join(dir, entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(b, old) {
				if parked != "" {
					t.Fatal("legacy inode parked more than once")
				}
				parked = filepath.Join(dir, entry.Name())
			}
		}
	}
	if active != 1 || parked == "" {
		t.Fatal("migration did not retain one inactive legacy copy and one current adapter")
	}
	return parked
}

func TestHiloPiMigratesOwnedLegacyWithoutDuplicateCaptureAdapter(t *testing.T) {
	o, l, old := hiloLegacyPi(t)
	legacy := filepath.Join(filepath.Dir(l.Extension), legacyExtensionName)
	before, err := os.Stat(legacy)
	if err != nil {
		t.Fatal(err)
	}
	status, err := Status(context.Background(), o)
	if err != nil || status.MCP != "legacy_extension_installed_migration_required" {
		t.Fatal("legacy status did not require migration", err)
	}
	if !bytes.Equal(mustRead(t, legacy), old) {
		t.Fatal("status mutated old adapter")
	}
	var writer *os.File
	if runtime.GOOS != "windows" {
		writer, err = os.OpenFile(legacy, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer writer.Close()
	}
	if _, err := Install(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	parked := hiloOnlyCurrentPi(t, l, old)
	after, err := os.Stat(parked)
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("legacy inode was replaced instead of retained", err)
	}
	current := mustRead(t, l.Extension)
	if !bytes.Contains(current, []byte(`pi.registerMcpServer("hilo",`)) || bytes.Contains(current, []byte(`pi.registerMcpServer("telara-memory",`)) {
		t.Fatal("current adapter registration identity incorrect")
	}
	if writer != nil {
		addition := []byte("// edit through retained old descriptor\n")
		if _, err := writer.Write(addition); err != nil {
			t.Fatal(err)
		}
		if b := mustRead(t, parked); !bytes.Equal(b, append(append([]byte(nil), old...), addition...)) {
			t.Fatal("retained descriptor writes were lost")
		}
	}
	if _, err := Install(context.Background(), o); err != nil {
		t.Fatal("idempotent current install failed", err)
	}
	if !bytes.Equal(current, mustRead(t, l.Extension)) {
		t.Fatal("retry changed current adapter")
	}
}

func TestHiloPiMigrationRefusesConflictsBeforePublication(t *testing.T) {
	for _, kind := range []string{"edited-legacy", "unreceipted-legacy", "dual-extension", "dual-receipt", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			o, l, old := hiloLegacyPi(t)
			dir := filepath.Dir(l.Extension)
			legacy := filepath.Join(dir, legacyExtensionName)
			ctx := context.Background()
			var cancel context.CancelFunc
			switch kind {
			case "edited-legacy":
				put(t, legacy, append(append([]byte(nil), old...), []byte("// owner edit\n")...))
			case "unreceipted-legacy":
				if err := os.Remove(filepath.Join(dir, legacyReceiptName)); err != nil {
					t.Fatal(err)
				}
			case "dual-extension":
				put(t, l.Extension, []byte("// independent current generation\n"))
			case "dual-receipt":
				put(t, filepath.Join(dir, receiptName), []byte(`{"version":1,"digest":"`+strings.Repeat("a", 64)+`"}`))
			case "canceled":
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			before := mustRead(t, legacy)
			_, err := Install(ctx, o)
			if kind == "canceled" {
				if !errors.Is(err, context.Canceled) {
					t.Fatal("canceled migration did not refuse", err)
				}
			} else if !errors.Is(err, ErrConflict) {
				t.Fatal("conflicting migration did not refuse", err)
			}
			if !bytes.Equal(before, mustRead(t, legacy)) {
				t.Fatal("refusal changed legacy adapter")
			}
			if kind != "dual-extension" {
				if _, err := os.Lstat(l.Extension); !os.IsNotExist(err) {
					t.Fatal("refusal published current adapter", err)
				}
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), ".hilo-remove-") {
					t.Fatal("refusal parked legacy inode")
				}
			}
		})
	}
}

func TestHiloPiMigrationResumesReachableInterruptedStates(t *testing.T) {
	for _, phase := range []string{"after-legacy-park", "after-legacy-receipt-removal", "after-current-receipt"} {
		t.Run(phase, func(t *testing.T) {
			o, l, old := hiloLegacyPi(t)
			dir := filepath.Dir(l.Extension)
			if phase == "after-current-receipt" {
				if _, err := Install(context.Background(), o); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(l.Extension); err != nil {
					t.Fatal(err)
				}
			} else {
				d, err := openDir(dir, false, true)
				if err != nil {
					t.Fatal(err)
				}
				unlock, err := d.lock()
				if err != nil {
					d.close()
					t.Fatal(err)
				}
				if phase == "after-legacy-park" {
					err = removeOwned(d, legacyExtensionName, digest(old))
				} else {
					err = migrateLegacyPi(context.Background(), d)
				}
				unlock()
				d.close()
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := os.Lstat(l.Extension); !os.IsNotExist(err) {
				t.Fatal("interrupted state already has current adapter", err)
			}
			if _, err := Install(context.Background(), o); err != nil {
				t.Fatal("reachable retry failed", err)
			}
			hiloOnlyCurrentPi(t, l, old)
		})
	}
}

func TestHiloUninstallRetiresOwnedLegacyPi(t *testing.T) {
	o, l, old := hiloLegacyPi(t)
	if _, err := Uninstall(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(l.Extension)
	for _, name := range []string{extensionName, receiptName, legacyExtensionName, legacyReceiptName} {
		if _, err := os.Lstat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatal("uninstall retained an active registration", err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".hilo-remove-") && bytes.Equal(mustRead(t, filepath.Join(dir, entry.Name())), old) {
			found = true
		}
	}
	if !found {
		t.Fatal("uninstall deleted the legacy recovery inode")
	}
}
