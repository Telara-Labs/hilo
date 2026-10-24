package vault

import "runtime"

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
