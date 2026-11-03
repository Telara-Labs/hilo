package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Telara-Labs/hilo/contract/internal/node/syncnode"
)

func TestLoginInspectionRefusesBeforeProfileOrVaultResolution(t *testing.T) {
	var out bytes.Buffer
	err := runLogin(context.Background(), []string{"--hosted", "--inspect"}, strings.NewReader(`{}`), &out)
	if !errors.Is(err, syncnode.ErrEnrollment) {
		t.Fatal("inspection did not parse before local path resolution", err)
	}
	if out.Len() != 0 {
		t.Fatal("refusal emitted an inspection")
	}
}

func TestLoginInspectionSelectorsCannotEnableUnboundEnrollment(t *testing.T) {
	for _, args := range [][]string{
		{"--inspect"}, {"--inspect", "--hosted", "--bound"},
		{"--inspect", "--hosted", "--key"}, {"--inspect", "--hosted", "--data-dir", "unused"},
		{"--inspect", "--hosted", "--install-dir", "unused"}, {"--bound"}, {"--bound", "--key"},
	} {
		var out bytes.Buffer
		err := runLogin(context.Background(), args, strings.NewReader(`{}`), &out)
		if err == nil || err.Error() != "invalid_arguments" || out.Len() != 0 {
			t.Fatal("invalid selector combination accepted")
		}
	}
}
