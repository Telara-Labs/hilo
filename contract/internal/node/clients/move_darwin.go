package clients

import "golang.org/x/sys/unix"

func move(from *directory, name string, to *directory) error {
	if !validName(name) {
		return unsafePath("move", name, "single filename required", nil)
	}
	return unix.RenameatxNp(from.fd, name, to.fd, name, unix.RENAME_EXCL)
}
func renameOwned(d *directory, from, to string) error {
	if !validName(from) || !validName(to) {
		return unsafePath("renameOwned", from+" -> "+to, "single source and destination filenames required", nil)
	}
	return unix.RenameatxNp(d.fd, from, d.fd, to, unix.RENAME_EXCL)
}
