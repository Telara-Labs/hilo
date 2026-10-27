//go:build !linux && !darwin

package store

import "os"

// Repository enrollment follows the native capture capability boundary. An OS
// without a held-descriptor owner checker cannot enroll an asserted source.
func openRepositoryPath(string) (*repositoryPath, error) {
	return nil, failure("repository_enrollment_unavailable")
}
func repositoryACL(*os.File) bool           { return false }
func repositoryIdentity(os.FileInfo) string { return "" }
func repositoryMode(os.FileInfo, bool) bool { return false }
