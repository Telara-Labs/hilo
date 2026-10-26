//go:build !windows

package store

import (
	"os"
	"path/filepath"
)

func publishPrivateRecord(source, target string, replace bool) error {
	if err := os.Rename(source, target); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(target))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
