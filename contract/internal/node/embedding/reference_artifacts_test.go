package embedding

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var referenceArtifactDir = flag.String("embedding-reference-artifacts", "", "local candidate development artifacts")

// Development-only probe. The fixed digests were observed for a pinned upstream
// candidate; they are not an authenticated release manifest or model selection.
func TestReferenceArtifactVerification(t *testing.T) {
	if *referenceArtifactDir == "" {
		t.Skip("development artifacts not supplied")
	}
	model, err := os.Open(filepath.Join(*referenceArtifactDir, "model.safetensors"))
	if err != nil {
		t.Fatal(err)
	}
	defer model.Close()
	tokenizer, err := os.Open(filepath.Join(*referenceArtifactDir, "tokenizer.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer tokenizer.Close()
	expected := ArtifactExpectation{ModelID: "potion-base-8M-dev", ModelSHA256: "f65d0f325faadc1e121c319e2faa41170d3fa07d8c89abd48ca5358d9a223de2", TokenizerSHA256: "e67e803f624fb4d67dea1c730d06e1067e1b14d830e2c2202569e3ef0f70bb50"}
	verified, err := VerifyArtifacts(expected, model, tokenizer)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("verified local candidate bytes model=%d tokenizer=%d", len(verified.ModelBytes()), len(verified.TokenizerBytes()))
}
