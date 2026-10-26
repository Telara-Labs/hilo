//go:build linux || darwin

package ipc

// ValidateDescriptorACL applies the existing native ACL policy to an already
// retained no-follow descriptor. Private forbids grants beyond owner access;
// non-private forbids untrusted mutation while allowing ordinary read access.
func ValidateDescriptorACL(fd int, private bool) error { return checkACL(fd, private) }
