//go:build linux || darwin

package store

import (
	"os"
	"path/filepath"
	"testing"
)

func repositoryProject(t *testing.T) (string, string) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(filepath.Join(root, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, ".git", "config"), []byte("[remote \"origin\"]\n url = git@github.com:acme/widgets.git\n"), 0644); err != nil {
		t.Fatal(err)
	}
	return root, "github.com/acme/widgets"
}
func TestRepositoryPathFiniteCanonicalForms(t *testing.T) {
	for raw, want := range map[string]string{"https://github.com/acme/widgets.git": "github.com/acme/widgets", "git@github.com:acme/widgets.git": "github.com/acme/widgets", "ssh://git@github.com/acme/widgets": "github.com/acme/widgets", "github.com/acme/widgets": "github.com/acme/widgets"} {
		got, err := canonicalRepositoryRemote(raw)
		if err != nil || got != want {
			t.Fatal(raw, got, err)
		}
	}
	for _, raw := range []string{"file:///tmp/repo", "https://github.com/acme/widgets?path=other", "https://github.com/acme/widgets#other", "github.com/acme/../widgets", "github.com/acme/widgets\n", "github.com/acme/", "https://github.com/acme/%77idgets"} {
		if _, err := canonicalRepositoryRemote(raw); err == nil {
			t.Fatal("ambiguous remote accepted", raw)
		}
	}
}
func TestRepositoryPathRejectsMutationAndReplacement(t *testing.T) {
	for _, mode := range []string{"valid", "root-write", "config-write", "symlink", "hardlink", "replacement", "include", "remote-change"} {
		t.Run(mode, func(t *testing.T) {
			root, remote := repositoryProject(t)
			name := filepath.Join(root, ".git", "config")
			switch mode {
			case "root-write":
				os.Chmod(root, 0775)
			case "config-write":
				os.Chmod(name, 0664)
			case "symlink":
				os.Rename(name, name+".old")
				os.Symlink(name+".old", name)
			case "hardlink":
				os.Link(name, name+".link")
			case "include":
				os.WriteFile(name, []byte("[include]\n path=other\n[remote \"origin\"]\nurl=https://github.com/acme/widgets\n"), 0644)
			}
			p, err := checkRepository(root, remote)
			if mode == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				p.close()
				return
			}
			if mode == "replacement" || mode == "remote-change" {
				if err != nil {
					t.Fatal(err)
				}
				defer p.close()
				if mode == "replacement" {
					os.Rename(name, name+".old")
				}
				os.WriteFile(name, []byte("[remote \"origin\"]\nurl=https://github.com/other/project\n"), 0644)
				if _, err = readRepositoryRemote(p); err == nil {
					got, _ := readRepositoryRemote(p)
					if got == remote {
						t.Fatal("changed config accepted")
					}
				}
				return
			}
			if err == nil {
				p.close()
				t.Fatal("unsafe repository accepted")
			}
		})
	}
}
