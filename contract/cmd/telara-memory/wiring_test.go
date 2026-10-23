package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/clients"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/install"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
)

func TestEveryServiceSubcommandRejectsInvalidFlags(t *testing.T) {
	for _, command := range []string{"daemon", "shim", "managed-daemon", "install", "uninstall", "status", "register", "start", "stop", "upgrade"} {
		for _, tail := range [][]string{{"--bad"}, {"extra"}, {"--install-dir", "relative"}} {
			var out bytes.Buffer
			err := run(context.Background(), append([]string{command}, tail...), strings.NewReader(""), &out)
			if err == nil {
				t.Fatalf("%s %v accepted", command, tail)
			}
		}
	}
	for _, command := range []string{"managed-daemon", "install", "upgrade"} {
		if err := run(context.Background(), []string{command}, strings.NewReader(""), &bytes.Buffer{}); err == nil {
			t.Fatal(command)
		}
	}
	for _, args := range [][]string{{"managed-daemon", "--data-dir", "/tmp/ignored"}, {"uninstall", "--source", "/tmp/ignored"}, {"daemon", "--start"}} {
		if err := run(context.Background(), args, strings.NewReader(""), &bytes.Buffer{}); err == nil {
			t.Fatal(args)
		}
	}
}
func TestStableInstallPublicCodes(t *testing.T) {
	for _, err := range []error{install.ErrUnavailable, install.ErrStopped, install.ErrUnverified, install.ErrUnsafe, install.ErrUpgrade, clients.ErrOptions, clients.ErrUnsafe, clients.ErrConflict, clients.ErrMalformed, clients.ErrBusy} {
		if got := publicCode(fmt.Errorf("secret wrapped %w", err)); got != err.Error() {
			t.Fatalf("%s", got)
		}
	}
}
func TestClientSubcommandsAllAndSelection(t *testing.T) {
	home := t.TempDir()
	os.Chmod(home, 0700)
	for _, command := range []string{"install", "uninstall", "status"} {
		for _, client := range []string{"", "claude", "codex", "cursor", "pi"} {
			var out bytes.Buffer
			args := []string{"clients", command, "--home", home, "--state-dir", filepath.Join(home, "state"), "--executable", filepath.Join(home, "node"), "--print"}
			if client != "" {
				args = append(args, "--client", client)
			}
			if err := run(context.Background(), args, strings.NewReader(""), &out); err != nil {
				t.Fatal(command, client, err)
			}
			decoder := json.NewDecoder(&out)
			count := 0
			for decoder.More() {
				var report clients.Report
				if err := decoder.Decode(&report); err != nil {
					t.Fatal(err)
				}
				count++
				if client != "" && string(report.Client) != client {
					t.Fatal("wrong client")
				}
			}
			want := 1
			if client == "" {
				want = 4
			}
			if count != want {
				t.Fatal(count, want)
			}
		}
	}
	for _, args := range [][]string{{"clients"}, {"clients", "unknown"}, {"clients", "status", "--client", "unknown"}, {"clients", "status", "extra"}} {
		if run(context.Background(), args, strings.NewReader(""), &bytes.Buffer{}) == nil {
			t.Fatal(args)
		}
	}
}
func TestHookFormsFailOpenAndPublish(t *testing.T) {
	home := t.TempDir()
	os.Chmod(home, 0700)
	state := filepath.Join(home, "state")
	for _, prefix := range [][]string{{"hook", "claude"}, {"hook", "--client", "claude"}} {
		var out bytes.Buffer
		args := append(append([]string{}, prefix...), "--home", home, "--state-dir", state)
		payload := `{"hook_event_name":"SessionStart","session_id":"01234567-89ab-4cde-8fab-0123456789ab","cwd":` + fmt.Sprintf("%q", home) + `,"prompt":"never persist this"}`
		if err := run(context.Background(), args, strings.NewReader(payload), &out); err != nil || out.Len() != 0 {
			t.Fatal(err, out.String())
		}
	}
	files, _ := filepath.Glob(filepath.Join(state, "spool", "claude", "new", "*.json"))
	if len(files) != 2 {
		t.Fatalf("hook publication %d", len(files))
	}
	for _, file := range files {
		b, err := os.ReadFile(file)
		if err != nil || bytes.Contains(b, []byte("never persist")) {
			t.Fatal("content persisted", err)
		}
	}
	for _, args := range [][]string{{"hook"}, {"hook", "--bad"}, {"hook", "unknown"}, {"hook", "claude", "--client", "codex"}, {"hook", "claude", "extra"}} {
		var out bytes.Buffer
		if err := run(context.Background(), args, strings.NewReader("not JSON"), &out); err != nil || out.Len() != 0 {
			t.Fatal(args, err)
		}
	}
	for _, payload := range []string{`{"session_id":"aaaaaaaa","session_id":"bbbbbbbb"}`, `[]`, strings.Repeat("x", (1<<20)+1)} {
		if err := run(context.Background(), []string{"hook", "claude", "--home", home, "--state-dir", state}, strings.NewReader(payload), &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
	}
	after, _ := filepath.Glob(filepath.Join(state, "spool", "claude", "new", "*.json"))
	if len(after) != 2 {
		t.Fatal("invalid input published")
	}
}
func TestReadinessWaitUsesDeadline(t *testing.T) {
	base := t.TempDir()
	os.Chmod(base, 0700)
	p, _ := ipc.Resolve(filepath.Join(base, "data"), filepath.Join(base, "run"))
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	if err := waitReadiness(ctx, p, &bytes.Buffer{}); err == nil || !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatal(err)
	}
}

func TestServiceSubcommandsReachRealInstallAPI(t *testing.T) {
	base := t.TempDir()
	os.Chmod(base, 0700)
	for _, command := range []string{"status", "register", "start", "stop", "uninstall"} {
		var out bytes.Buffer
		err := run(context.Background(), []string{command, "--install-dir", filepath.Join(base, command)}, strings.NewReader(""), &out)
		if err == nil || err.Error() == "invalid_command" || err.Error() == "invalid_arguments" {
			t.Fatalf("%s not dispatched %v", command, err)
		}
	}
	for _, command := range []string{"install", "upgrade"} {
		var out bytes.Buffer
		err := run(context.Background(), []string{command, "--install-dir", filepath.Join(base, command), "--source", filepath.Join(base, "missing"), "--sha256", strings.Repeat("0", 64), "--version", "fixture"}, strings.NewReader(""), &out)
		if err == nil || err.Error() == "invalid_command" || err.Error() == "release_inputs_required" {
			t.Fatalf("%s not dispatched %v", command, err)
		}
	}
}
