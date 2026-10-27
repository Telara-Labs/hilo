package store

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

type heldRepositoryPath struct {
	path     string
	file     *os.File
	identity string
}
type repositoryPath struct {
	root, config string
	digest       string
	held         []heldRepositoryPath
}

func (p *repositoryPath) close() {
	for _, h := range p.held {
		_ = h.file.Close()
	}
}
func (p *repositoryPath) current() error {
	for _, h := range p.held {
		actual, err := h.file.Stat()
		if err != nil {
			return failure("repository_changed")
		}
		named, err := os.Lstat(h.path)
		inside := h.path == p.root || strings.HasPrefix(h.path, p.root+string(filepath.Separator))
		if err != nil || named.Mode()&os.ModeSymlink != 0 || !os.SameFile(actual, named) || repositoryIdentity(actual) != h.identity || !repositoryMode(actual, inside) || !repositoryACL(h.file) {
			return failure("repository_changed")
		}
		if h.path == p.config && p.digest != "" {
			data, e := io.ReadAll(io.NewSectionReader(h.file, 0, 65537))
			sum := sha256.Sum256(data)
			clear(data)
			if e != nil || actual.Size() > 65536 || hex.EncodeToString(sum[:]) != p.digest {
				return failure("repository_changed")
			}
		}

	}
	return nil
}

// canonicalRepositoryRemote handles the finite common Git URL forms without
// executing Git, reading includes, following helpers or retaining credentials.
func canonicalRepositoryRemote(raw string) (string, error) {
	if raw == "" || len(raw) > 4096 || !utf8.ValidString(raw) || strings.IndexFunc(raw, unicode.IsSpace) >= 0 || strings.IndexFunc(raw, unicode.IsControl) >= 0 || strings.Contains(raw, "\\") {
		return "", failure("invalid_repository")
	}
	value := raw
	if strings.Contains(value, "://") {
		u, err := url.Parse(value)
		if err != nil || u.Host == "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || u.Opaque != "" || (u.Scheme != "https" && u.Scheme != "http" && u.Scheme != "ssh" && u.Scheme != "git") {
			return "", failure("invalid_repository")
		}
		value = strings.ToLower(u.Host) + u.Path
	} else if at := strings.IndexByte(value, '@'); at >= 0 {
		colon := strings.IndexByte(value[at+1:], ':')
		if colon < 0 {
			return "", failure("invalid_repository")
		}
		colon += at + 1
		value = strings.ToLower(value[at+1:colon]) + "/" + value[colon+1:]
	}
	value = strings.TrimSuffix(strings.TrimSuffix(value, "/"), ".git")
	parts := strings.Split(value, "/")
	if len(parts) < 3 || strings.ContainsAny(value, "@?#%") || strings.ContainsAny(parts[0], ":") {
		return "", failure("invalid_repository")
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return "", failure("invalid_repository")
		}
	}
	parts[0] = strings.ToLower(parts[0])
	return strings.Join(parts, "/"), nil
}

func readRepositoryRemote(p *repositoryPath) (string, error) {
	var f *os.File
	for _, h := range p.held {
		if h.path == p.config {
			f = h.file
		}
	}
	if f == nil {
		return "", failure("invalid_repository")
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", failure("repository_changed")
	}
	data, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil || len(data) > 65536 || !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		return "", failure("invalid_repository")
	}
	defer clear(data)
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	if p.digest != "" && p.digest != digest {
		return "", failure("repository_changed")
	}
	p.digest = digest
	scanner := bufio.NewScanner(bytes.NewReader(data))
	section := ""
	remote := ""
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = strings.ToLower(line)
			if strings.HasPrefix(section, "[include") {
				return "", failure("repository_include_unsupported")
			}
			continue
		}
		if section != "[remote \"origin\"]" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(strings.ToLower(key)) != "url" {
			continue
		}
		if remote != "" {
			return "", failure("ambiguous_repository")
		}
		value = strings.TrimSpace(value)
		if strings.HasPrefix(value, "\"") {
			value, err = strconv.Unquote(value)
			if err != nil {
				return "", failure("invalid_repository")
			}
		}
		remote, err = canonicalRepositoryRemote(value)
		if err != nil {
			return "", err
		}
	}
	if scanner.Err() != nil || remote == "" {
		return "", failure("invalid_repository")
	}
	if err := p.current(); err != nil {
		return "", err
	}
	return remote, nil
}

func checkRepository(root, remote string) (*repositoryPath, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || len(root) > 4096 {
		return nil, failure("invalid_repository")
	}
	canonical, err := canonicalRepositoryRemote(remote)
	if err != nil || canonical != remote {
		return nil, failure("invalid_repository")
	}
	p, err := openRepositoryPath(root)
	if err != nil {
		return nil, err
	}
	actual, err := readRepositoryRemote(p)
	if err != nil || actual != remote {
		p.close()
		return nil, failure("repository_changed")
	}
	return p, nil
}
