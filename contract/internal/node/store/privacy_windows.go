//go:build windows

package store

import "github.com/Telara-Labs/hilo/contract/internal/node/ipc"

// Directory creation uses a protected inheritable owner-only DACL, so native
// SQLite main/WAL/SHM files and atomic profile writes inherit private access.
// Existing broad ACLs, untrusted ancestors and reparse points are refused.
func privateDir(path string) error {
	if err := ipc.ValidateDir(path, true); err != nil {
		return failure("unsafe_path")
	}
	return nil
}
func privateFile(path string) error {
	if err := ipc.ValidatePrivateFile(path); err != nil {
		return failure("unsafe_path")
	}
	return nil
}
