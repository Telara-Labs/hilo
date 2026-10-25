package vault

import (
	"os"
	"path/filepath"
	"runtime"
)

// nativeCustody is false only in builds that cannot reach native custody.
var nativeCustody = true

// Location identifies the custody store without a potentially interactive query.
func Location() string {
	switch runtime.GOOS {
	case "darwin":
		return "user default Keychain via Security.framework"
	case "linux":
		return "Secret Service collection alias telara-memory on the existing session bus"
	case "windows":
		return "current user Windows Credential Manager"
	}
	return "unavailable native vault"
}

// Backend names the native custody backend this build uses, without opening
// it. A build without native custody reports unavailable; there is no fallback.
func Backend() string {
	if !nativeCustody {
		return "unavailable"
	}
	switch runtime.GOOS {
	case "darwin":
		return "macos_keychain"
	case "linux":
		return "linux_secret_service"
	case "windows":
		return "windows_credential_manager"
	}
	return "unavailable"
}

// CustodyRecord reports whether a profile has pinned its custody location.
// It reads only file metadata, never the record contents or any secret.
// Platforms without a recorded location report "not_applicable".
func CustodyRecord(data string) string {
	if runtime.GOOS == "windows" {
		return "not_applicable"
	}
	info, err := os.Lstat(filepath.Join(data, "custody-location.json"))
	switch {
	case os.IsNotExist(err):
		return "absent"
	case err != nil:
		return "unreadable"
	case !info.Mode().IsRegular():
		return "unsafe"
	}
	return "present"
}
