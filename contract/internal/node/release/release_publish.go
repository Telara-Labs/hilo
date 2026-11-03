package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/Telara-Labs/hilo/contract/releaseauth"
)

// Publication copies to independent inodes, authenticates the copied tree and
// commits the entire tree with a no-replace rename. No source hard link survives.
// Another process with the same user's authority can still change owned output
// afterward. Installers must authenticate metadata and hash their copied image.
var errReleasePublicationIncomplete = errors.New("release publication incomplete")

const releasePublicationDomain = "telara-memory-release-v1\x00"

type releasePublicationHook func(phase, source, destination string)

type releaseOwnedEntry struct {
	path string
	info os.FileInfo
}

// Cleanup is deliberately conservative. A replaced directory or child is not
// recursively deleted. Unknown names prevent removal of their parent. Retained
// private staging is preferable to deleting foreign work after ownership loss.
type releaseOwnedTree struct {
	path    string
	root    *os.Root
	info    os.FileInfo
	entries []releaseOwnedEntry
}

func newReleaseOwnedTree(parent, pattern string) (*releaseOwnedTree, error) {
	path, err := os.MkdirTemp(parent, pattern)
	if err != nil {
		return nil, errReleasePublicationIncomplete
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, errReleasePublicationIncomplete
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, errReleasePublicationIncomplete
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(opened, info) {
		_ = root.Close()
		return nil, errReleasePublicationIncomplete
	}
	return &releaseOwnedTree{path: path, root: root, info: info}, nil
}

func (t *releaseOwnedTree) sameRoot() bool {
	info, err := os.Lstat(t.path)
	return err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 && info.Mode() == t.info.Mode() && os.SameFile(info, t.info)
}

func (t *releaseOwnedTree) remember(name string, info os.FileInfo) {
	t.entries = append(t.entries, releaseOwnedEntry{name, info})
}

func (t *releaseOwnedTree) cleanup() {
	defer t.root.Close()
	// The handle is anchored to the original directory even if its path moved.
	for i := len(t.entries) - 1; i >= 0; i-- {
		entry := t.entries[i]
		info, err := t.root.Lstat(entry.path)
		if err == nil && info.Mode()&os.ModeSymlink == 0 && os.SameFile(info, entry.info) {
			_ = t.root.Remove(entry.path)
		}
	}
	if t.sameRoot() {
		_ = os.Remove(t.path) // Empty-directory removal only, never RemoveAll.
	}
}

func sameReleaseFile(a, b os.FileInfo) bool {
	return a != nil && b != nil && os.SameFile(a, b) && a.Size() == b.Size() &&
		a.Mode() == b.Mode() && a.ModTime().Equal(b.ModTime())
}

func copyReleaseFile(ctx context.Context, source string, tree *releaseOwnedTree, name string, hook releasePublicationHook) error {
	before, err := os.Lstat(source)
	if err != nil || !before.Mode().IsRegular() || before.Size() < 0 || before.Size() > 512<<20 {
		return errReleasePublicationIncomplete
	}
	in, err := os.Open(source)
	if err != nil {
		return errReleasePublicationIncomplete
	}
	defer in.Close()
	opened, err := in.Stat()
	if err != nil || !sameReleaseFile(before, opened) {
		return errReleasePublicationIncomplete
	}
	out, err := tree.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errReleasePublicationIncomplete
	}
	defer out.Close()
	created, err := out.Stat()
	if err != nil {
		return errReleasePublicationIncomplete
	}
	tree.remember(name, created)
	destination := filepath.Join(tree.path, name)
	if hook != nil {
		hook("opened", source, destination)
	}
	buffer := make([]byte, 64*1024)
	var copied int64
	for {
		if ctx.Err() != nil {
			return errReleasePublicationIncomplete
		}
		n, readErr := in.Read(buffer)
		if n > 0 {
			if copied+int64(n) > 512<<20 {
				return errReleasePublicationIncomplete
			}
			if written, e := out.Write(buffer[:n]); e != nil || written != n {
				return errReleasePublicationIncomplete
			}
			copied += int64(n)
			if hook != nil {
				hook("copied-chunk", source, destination)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return errReleasePublicationIncomplete
		}
	}
	after, err := in.Stat()
	current, pathErr := os.Lstat(source)
	if err != nil || pathErr != nil || copied != before.Size() || !sameReleaseFile(before, after) || !sameReleaseFile(before, current) {
		return errReleasePublicationIncomplete
	}
	if out.Chmod(safeArtifactMode(before.Mode())) != nil || out.Sync() != nil {
		return errReleasePublicationIncomplete
	}
	final, err := out.Stat()
	if out.Close() != nil {
		return errReleasePublicationIncomplete
	}
	current, pathErr = tree.root.Lstat(name)
	if err != nil || pathErr != nil || !sameReleaseFile(final, current) || os.SameFile(opened, final) {
		return errReleasePublicationIncomplete
	}
	// Replace the creation-time size with the completed descriptor's identity.
	tree.entries[len(tree.entries)-1].info = final
	return nil
}

func (t *releaseOwnedTree) stable() bool {
	if !t.sameRoot() {
		return false
	}
	for _, entry := range t.entries {
		info, err := t.root.Lstat(entry.path)
		if err != nil || !sameReleaseFile(info, entry.info) {
			return false
		}
	}
	return true
}

func publishReleaseTrees(ctx context.Context, dirs []string, output, tag string, verify func(string) (releaseauth.Provenance, error), hook releasePublicationHook) error {
	if ctx == nil || ctx.Err() != nil || verify == nil || len(dirs) < 1 || len(dirs) > 2 {
		return errReleasePublicationIncomplete
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		return errReleasePublicationIncomplete
	}
	tree, err := newReleaseOwnedTree(filepath.Dir(output), ".hilo-verified-publication-")
	if err != nil {
		return errReleasePublicationIncomplete
	}
	defer tree.cleanup()
	var first releaseauth.Provenance
	for i, source := range dirs {
		prefix, family := "hilo-", ""
		if len(dirs) == 2 {
			family = []string{"legacy", "hilo"}[i]
			if i == 0 {
				prefix = "telara-memory-"
			}
			if tree.root.Mkdir(family, 0700) != nil {
				return errReleasePublicationIncomplete
			}
			info, e := tree.root.Lstat(family)
			if e != nil {
				return errReleasePublicationIncomplete
			}
			tree.remember(family, info)
		}
		files, e := familyFiles(source, prefix)
		if e != nil || len(files) != len(targets)+3 {
			return errReleasePublicationIncomplete
		}
		sort.Strings(files)
		for _, file := range files {
			if copyReleaseFile(ctx, filepath.Join(source, file), tree, filepath.Join(family, file), hook) != nil {
				return errReleasePublicationIncomplete
			}
		}
		if hook != nil {
			hook("before-verify", source, filepath.Join(tree.path, family))
		}
		p, e := verify(filepath.Join(tree.path, family))
		if e != nil || !p.Signed || p.Source != tag || p.Verification != "clean-tag-export-signed" || i > 0 && p != first {
			return errReleasePublicationIncomplete
		}
		first = p
	}
	// Directory mtimes change while adding children. Capture completed values.
	for i := range tree.entries {
		if tree.entries[i].info.IsDir() {
			info, e := tree.root.Lstat(tree.entries[i].path)
			if e != nil || !os.SameFile(info, tree.entries[i].info) {
				return errReleasePublicationIncomplete
			}
			tree.entries[i].info = info
		}
	}
	if hook != nil {
		hook("before-commit", tree.path, output)
	}
	if !tree.stable() || ctx.Err() != nil || renameReleaseTreeNoReplace(tree.path, output) != nil {
		return errReleasePublicationIncomplete
	}
	// Do not remove anything at output on an error after commit. A replacement
	// there is foreign. The original handle remains safe for owned cleanup.
	tree.path = output
	if hook != nil {
		hook("committed", "", output)
	}
	if !tree.stable() {
		// Leave final output untouched on ownership loss.
		tree.entries = nil
		tree.path = ""
		return errReleasePublicationIncomplete
	}
	// The final tree has no aliases to the build/signing staging tree. Every
	// descriptor identity is checked around final signature/hash verification.
	for i := range dirs {
		family := ""
		if len(dirs) == 2 {
			family = []string{"legacy", "hilo"}[i]
		}
		p, e := verify(filepath.Join(output, family))
		if e != nil || p != first || !tree.stable() || ctx.Err() != nil {
			tree.entries = nil
			tree.path = ""
			return errReleasePublicationIncomplete
		}
	}
	// Successful output belongs to the caller. Cleanup closes only its handle.
	tree.entries = nil
	tree.path = ""
	return nil
}
