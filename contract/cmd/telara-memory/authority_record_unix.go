//go:build !windows

package main

import (
	"errors"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
	"io"
	"os"
	"path/filepath"
)

func safeAuthorityFile(_ string, st os.FileInfo) bool {
	return st.Mode().IsRegular() && st.Mode().Perm() == 0600
}
func readAuthorityRecord(data string) ([]byte, error) {
	if _, e := os.Lstat(filepath.Join(data, pendingAuthority)); e != nil {
		return nil, e
	}
	if ipc.ValidateDir(data, false) != nil {
		return nil, errors.New("runtime_authority_unavailable")
	}
	path := filepath.Join(data, pendingAuthority)
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !safeAuthorityFile(path, before) || before.Size() > 1024 {
		return nil, errors.New("runtime_authority_unavailable")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) {
		return nil, errors.New("runtime_authority_unavailable")
	}
	b, err := io.ReadAll(io.LimitReader(f, 1025))
	if err != nil || len(b) > 1024 {
		return nil, errors.New("runtime_authority_unavailable")
	}
	return b, nil
}
func syncAuthorityDir(data string) error {
	f, e := os.Open(data)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func writeAuthorityRecord(data string, b []byte) error {
	if ipc.ValidateDir(data, false) != nil {
		return errors.New("runtime_authority_unavailable")
	}
	f, e := os.CreateTemp(data, ".authority-pending-")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if _, e = f.Write(b); e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	if e = os.Rename(name, filepath.Join(data, pendingAuthority)); e != nil {
		return e
	}
	return syncAuthorityDir(data)
}
