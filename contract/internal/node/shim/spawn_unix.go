//go:build darwin || linux

package shim

// There is no verified installed-artifact launch adapter on this platform.
// Spawn refuses unmanaged autostart rather than reopening an executable path.
