//go:build darwin || linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestDoctorCommandTextAndJSON(t *testing.T) {
	n := startInstalledNode(t)
	n.callTool("telara_task_create", map[string]any{"goal": "doctorcontentmustnotappear"})
	installDir := filepath.Join(filepath.Dir(n.paths.Data), "no-install")
	args := []string{"doctor", "--install-dir", installDir, "--data-dir", n.paths.Data, "--run-dir", n.paths.Run, "--home", n.home}
	var out bytes.Buffer
	if err := run(context.Background(), append(args, "--json"), strings.NewReader(""), &out); err != nil {
		t.Fatal(publicCode(err))
	}
	var r struct {
		Install struct {
			State string `json:"state"`
		} `json:"install"`
		Daemon struct {
			Reachable  bool `json:"reachable"`
			StoreWired bool `json:"store_wired"`
		} `json:"daemon"`
		KeyStore struct {
			RuntimeAuthority string `json:"runtime_authority"`
		} `json:"key_store"`
		Store struct {
			State string `json:"state"`
		} `json:"store"`
		Hooks    []json.RawMessage `json:"hooks"`
		Problems []string          `json:"problems"`
	}
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatal(err, out.String())
	}
	if r.Install.State != "absent" || !r.Daemon.Reachable || !r.Daemon.StoreWired || r.KeyStore.RuntimeAuthority != "loaded" || r.Store.State != "ok" || len(r.Hooks) != 4 {
		t.Fatalf("%+v", r)
	}
	if strings.Contains(out.String(), "doctorcontentmustnotappear") {
		t.Fatal("doctor printed record content")
	}
	out.Reset()
	if err := run(context.Background(), args, strings.NewReader(""), &out); err != nil {
		t.Fatal(publicCode(err))
	}
	if !strings.HasPrefix(out.String(), "hilo doctor\n") || !strings.Contains(out.String(), "\nScrub\n") || strings.Contains(out.String(), "doctorcontentmustnotappear") {
		t.Fatal(out.String())
	}
	if err := run(context.Background(), []string{"doctor", "extra"}, strings.NewReader(""), &out); publicCode(err) != "invalid_arguments" {
		t.Fatal(err)
	}
}
