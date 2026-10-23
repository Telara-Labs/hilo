//go:build darwin || linux

package shim

// Spawn uses the shared receipt verifier and the platform service manager.
// No detached executable fallback is provided on this platform.
