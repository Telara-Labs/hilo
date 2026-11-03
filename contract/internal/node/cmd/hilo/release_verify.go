package main

import (
	"encoding/json"
	"flag"
	"io"

	"github.com/Telara-Labs/hilo/contract/releaseauth"
)

func runVerifyRelease(args []string, out io.Writer) error {
	f := flag.NewFlagSet("verify-release", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	dir := f.String("dir", "", "Release directory containing all binaries and signed manifest")
	if f.Parse(args) != nil || f.NArg() != 0 || *dir == "" {
		return publicError("invalid_arguments")
	}
	p, err := releaseauth.Verify(*dir)
	if err != nil {
		return publicError("release_verification_failed")
	}
	return json.NewEncoder(out).Encode(p)
}
