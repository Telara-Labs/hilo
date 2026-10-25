package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	nodesync "github.com/Telara-Labs/telara-memory/contract/internal/node/sync"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/syncnode"
	"github.com/Telara-Labs/telara-memory/contract/sig"
)

type cliVault struct {
	mu    sync.Mutex
	items map[string][]byte
}

func (v *cliVault) Put(_ context.Context, h string, b []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, ok := v.items[h]; ok {
		return fmt.Errorf("exists")
	}
	v.items[h] = append([]byte(nil), b...)
	return nil
}
func (v *cliVault) Get(_ context.Context, h string) ([]byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	b, ok := v.items[h]
	if !ok {
		return nil, fmt.Errorf("missing")
	}
	return append([]byte(nil), b...), nil
}
func (v *cliVault) Delete(_ context.Context, h string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.items, h)
	return nil
}

func TestSyncCommandsEnrollStatusDisableLogout(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(base, "data")
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	genesis, machine := sig.KeyID(pub), "11111111-1111-4111-8111-111111111111"
	st, err := store.Open(context.Background(), store.Options{Dir: dir, PinnedGenesisID: genesis, LocalMachineID: machine})
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	manifest, _ := json.Marshal(map[string]any{"version": 1, "owner": genesis, "machine": machine, "credential": "22222222-2222-4222-8222-222222222222", "vault_handle": strings.Repeat("ab", 16)})
	if err := store.WriteInstalledRecord(dir, manifest); err != nil {
		t.Fatal(err)
	}
	v := &cliVault{items: map[string][]byte{}}
	old := syncVault
	syncVault = func(string) syncnode.SecretVault { return v }
	t.Cleanup(func() { syncVault = old })
	call := func(in string, args ...string) (map[string]any, error) {
		var out bytes.Buffer
		err := run(context.Background(), append([]string{"sync"}, append(args, "--data-dir", dir)...), strings.NewReader(in), &out)
		var m map[string]any
		if err == nil {
			_ = json.Unmarshal(bytes.TrimSpace(out.Bytes()), &m)
		}
		return m, err
	}
	status, err := call("", "status")
	if err != nil || status["configured"] != false || status["enabled"] != false {
		t.Fatalf("default status %v %v", status, err)
	}
	if _, err := call("", "enable"); err == nil {
		t.Fatal("enabled without enrollment")
	}
	key, err := call("", "key")
	if err != nil || key["jkt"] == "" {
		t.Fatalf("key %v %v", key, err)
	}
	again, _ := call("", "key")
	if again["jkt"] != key["jkt"] {
		t.Fatal("key not stable")
	}
	auth, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk, _ := nodesync.PublicJWKOf(&auth.PublicKey)
	tsk, _, _ := ed25519.GenerateKey(rand.Reader)
	enrollment := syncnode.Enrollment{Origin: "https://memory.example", Tenant: "tenant", User: "user", Config: "config", AuthIssuer: "https://auth.example", AuthKey: jwk, ServiceKeys: []syncnode.ServiceKey{{KeyID: sig.KeyID(tsk), Public: base64.RawURLEncoding.EncodeToString(tsk)}}, Grant: nodesync.MemoryGrant{Ops: []string{"push"}, Repos: []string{"r1:" + strings.Repeat("a", 64)}, Origin: "local", GenesisID: genesis, DeviceID: machine, ExpiresAtUnix: time.Now().Add(time.Hour).Unix()}, RefreshToken: "telara_mcp_bootstrap"}
	wrong := enrollment
	wrong.Grant.DeviceID = "33333333-3333-4333-8333-333333333333"
	raw, _ := json.Marshal(wrong)
	if _, err := call(string(raw), "enroll"); err == nil || publicCode(err) != "sync_identity_mismatch" {
		t.Fatalf("foreign grant accepted: %v", err)
	}
	raw, _ = json.Marshal(enrollment)
	if _, err := call(string(raw), "enroll"); err != nil {
		t.Fatal(err)
	}
	if rule, err := call("", "select", "--id", "work", "--repo", "r1:"+strings.Repeat("a", 64)); err != nil || rule["profile"] != "push-metadata" {
		t.Fatalf("select %v %v", rule, err)
	}
	if _, err := call("", "select", "--id", "bad", "--repo", "github.com/acme/api"); err == nil {
		t.Fatal("non repo id selected")
	}
	status, err = call("", "status")
	if err != nil || status["enabled"] != true || status["enrolled"] != true || len(status["rules"].([]any)) != 1 {
		t.Fatalf("status %v %v", status, err)
	}
	if bytes.Contains(mustJSON(status), []byte("telara_mcp_bootstrap")) {
		t.Fatal("status exposed the refresh credential")
	}
	if _, err := call("", "disable"); err != nil {
		t.Fatal(err)
	}
	if status, _ = call("", "status"); status["enabled"] != false {
		t.Fatal("disable ignored")
	}
	if _, err := call("", "unselect", "--id", "work"); err != nil {
		t.Fatal(err)
	}
	if _, err := call("", "logout"); err != nil {
		t.Fatal(err)
	}
	if status, _ = call("", "status"); status["configured"] != false || len(v.items) != 0 {
		t.Fatalf("logout left %v and %d slots", status, len(v.items))
	}
	if _, err := call("", "status", "--id", "x"); err == nil {
		t.Fatal("unexpected flag accepted")
	}
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }
