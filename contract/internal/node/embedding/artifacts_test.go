package embedding

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func digest(data string) string { s := sha256.Sum256([]byte(data)); return hex.EncodeToString(s[:]) }
func TestVerifyArtifactsSnapshotsAndDigests(t *testing.T) {
	e := ArtifactExpectation{ModelID: "candidate-v1", ModelSHA256: digest("model"), TokenizerSHA256: digest("tokenizer")}
	v, err := VerifyArtifacts(e, strings.NewReader("model"), strings.NewReader("tokenizer"))
	if err != nil || v.Identity() != e {
		t.Fatalf("verify %v", err)
	}
	m := v.ModelBytes()
	m[0] = 'X'
	if string(v.ModelBytes()) != "model" {
		t.Fatal("mutable model escaped")
	}
	if v, err := VerifyArtifacts(e, strings.NewReader("changed"), strings.NewReader("tokenizer")); err == nil || v != nil {
		t.Fatal("accepted changed model")
	}
	if v, err := VerifyArtifacts(e, strings.NewReader("model"), strings.NewReader("changed")); err == nil || v != nil {
		t.Fatal("accepted changed tokenizer")
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }
func TestVerifyArtifactsRejectsInvalidInput(t *testing.T) {
	e := ArtifactExpectation{ModelID: "candidate", ModelSHA256: digest("model"), TokenizerSHA256: digest("tokenizer")}
	if v, err := VerifyArtifacts(e, failingReader{}, strings.NewReader("tokenizer")); err == nil || v != nil {
		t.Fatal("accepted failed read")
	}
	if v, err := VerifyArtifacts(e, strings.NewReader(""), strings.NewReader("tokenizer")); err == nil || v != nil {
		t.Fatal("accepted empty artifact")
	}
	e.ModelID = "../model"
	if _, err := VerifyArtifacts(e, strings.NewReader("model"), strings.NewReader("tokenizer")); err == nil {
		t.Fatal("accepted invalid identity")
	}
	e.ModelID = "candidate"
	e.ModelSHA256 = strings.ToUpper(digest("model"))
	if _, err := VerifyArtifacts(e, strings.NewReader("model"), strings.NewReader("tokenizer")); err == nil {
		t.Fatal("accepted noncanonical digest")
	}
	want, _ := parseDigest(digest("abcd"))
	if _, err := readArtifact(bytes.NewBufferString("abcd"), want, 3); err == nil {
		t.Fatal("accepted oversized artifact")
	}
}
