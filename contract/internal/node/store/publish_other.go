//go:build !windows

package store

import (
	"os"
	"path/filepath"
)

func publishPrivateRecord(source, target string, replace bool) error {
	if replace {
		if err := os.Rename(source, target); err != nil {
			return err
		}
	} else {
		// Same-directory hard-link publication is atomic and fails if target
		// exists. A prior Lstat followed by Rename does not preserve no-replace.
		if err := os.Link(source, target); err != nil {
			return err
		}
		// The caller also defers temporary-file removal. Failure here retains
		// the committed target and reports an incomplete publication cleanup.
		if err := os.Remove(source); err != nil {
			return err
		}
	}
	dir, err := os.Open(filepath.Dir(target))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
