package store

import (
	"net/url"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSQLiteURIUsesNativeAbsolutePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a # b.sqlite")
	got := SQLiteURI(path, "mode=ro&immutable=1")
	u, err := url.Parse(got)
	if err != nil || u.Scheme != "file" || u.Host != "" || u.RawQuery != "mode=ro&immutable=1" {
		t.Fatal(got, err)
	}
	want := filepath.ToSlash(path)
	if runtime.GOOS == "windows" {
		want = "/" + want
	}
	if u.Path != want || strings.Contains(got, "%5C") || !strings.Contains(got, "%23") {
		t.Fatal("native path was changed by URI encoding", got, want)
	}
}
