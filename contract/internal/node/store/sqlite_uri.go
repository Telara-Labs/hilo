package store

import (
	"net/url"
	"path/filepath"
	"strings"
)

// SQLiteURI encodes a previously validated native absolute path as a SQLite
// file URI. Windows drive paths require forward slashes and a leading slash;
// escaping native backslashes produces a different, unopenable filename.
func SQLiteURI(path, query string) string {
	path = filepath.ToSlash(path)
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return (&url.URL{Scheme: "file", Path: path, RawQuery: query}).String()
}
