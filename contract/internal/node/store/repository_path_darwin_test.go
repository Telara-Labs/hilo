//go:build darwin

package store

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRepositoryPathRejectsNamedWriteACL(t *testing.T) {
	for _, on := range []string{"root", "config"} {
		t.Run(on, func(t *testing.T) {
			root, remote := repositoryProject(t)
			name := root
			if on == "config" {
				name = filepath.Join(root, ".git", "config")
			}
			before, err := os.Stat(name)
			if err != nil {
				t.Fatal(err)
			}
			p, err := checkRepository(root, remote)
			if err != nil {
				t.Fatal(err)
			}
			defer p.close()
			if output, err := exec.Command("/bin/chmod", "+a", "everyone allow write,append,writeattr,writeextattr", name).CombinedOutput(); err != nil {
				t.Fatal("synthetic ACL setup", err, string(output))
			}
			defer exec.Command("/bin/chmod", "-N", name).Run()
			after, err := os.Stat(name)
			if err != nil || before.Mode().Perm() != after.Mode().Perm() {
				t.Fatal("ACL fixture changed mode bits", err)
			}
			if p.current() == nil {
				t.Fatal("retained path accepted named writer ACL")
			}
			if next, err := checkRepository(root, remote); err == nil {
				next.close()
				t.Fatal("initial open accepted named writer ACL")
			}
		})
	}
}
