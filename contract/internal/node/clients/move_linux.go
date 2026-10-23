package clients

import "golang.org/x/sys/unix"

func move(from *directory, name string, to *directory) error {
	if !validName(name) {
		return ErrUnsafe
	}
	return unix.Renameat2(from.fd, name, to.fd, name, unix.RENAME_NOREPLACE)
}
func renameOwned(d *directory, from, to string) error {
	if !validName(from) || !validName(to) {
		return ErrUnsafe
	}
	return unix.Renameat2(d.fd, from, d.fd, to, unix.RENAME_NOREPLACE)
}
