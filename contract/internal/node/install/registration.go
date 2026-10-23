package install

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"strconv"
	"strings"
	"unicode/utf16"
)

// registered reads the loaded configuration, not merely the on-disk definition.
// It verifies the actual program's digest and owner through the trusted-file
// verifier. A same-label collision is never permission to start or replace it.
func registered(ctx context.Context, r Record) error {
	var b []byte
	var e error
	switch r.Platform {
	case "darwin":
		b, e = nativeCommand(ctx, r.Platform, "print", service(r))
		if e != nil {
			missing := "Could not find service \"" + r.Label + "\" in domain for user gui: " + r.UserID
			diagnostic := strings.TrimSpace(string(b))
			if diagnostic == missing || diagnostic == "Bad request.\n"+missing {
				return errAbsent
			}
			return ErrUnavailable
		}
		if len(b) >= 65536 {
			return ErrUnverified
		}
		e = verifyLaunchRegistration(b, r)
	case "linux":
		b, e = nativeCommand(ctx, r.Platform, "--user", "show", service(r), "--property=LoadState,FragmentPath,DropInPaths,User,ExecCondition,ExecStartPre,ExecStartPost,ExecReload,ExecStop,ExecStopPost,Environment,EnvironmentFiles,RootDirectory,RootImage")
		if e != nil {
			return ErrUnavailable
		}
		if len(b) >= 65536 {
			return ErrUnverified
		}
		e = verifySystemdRegistration(b, r)
		if e == nil {
			b, e = nativeCommand(ctx, "linux-bus", "--user", "--json=short", "get-property", "org.freedesktop.systemd1", systemdObject(r), "org.freedesktop.systemd1.Service", "ExecStart")
			if e != nil {
				return ErrUnavailable
			}
			e = verifySystemdExec(b, r)
		}
	case "windows":
		// A successful complete inventory distinguishes missing tasks from denied
		// queries without relying on localized Windows error messages.
		b, e = nativeCommand(ctx, r.Platform, "/Query", "/FO", "CSV", "/NH")
		if e != nil || len(b) >= 65536 {
			return ErrUnavailable
		}
		rows, ce := csv.NewReader(bytes.NewReader(b)).ReadAll()
		if ce != nil {
			return ErrUnverified
		}
		found := false
		for _, row := range rows {
			if len(row) > 0 && strings.EqualFold(row[0], `\`+r.Label) {
				found = true
			}
		}
		if !found {
			return errAbsent
		}
		b, e = nativeCommand(ctx, r.Platform, "/Query", "/TN", r.Label, "/XML")
		if e != nil {
			return ErrUnavailable
		}
		if len(b) >= 65536 {
			return ErrUnverified
		}
		e = verifyTaskRegistration(b, r)
	default:
		return ErrUnavailable
	}
	if e != nil {
		return e
	}
	v, e := verify(r.Executable, r.SHA256)
	if e != nil {
		return e
	}
	return v.Close()
}

func verifyLaunchRegistration(b []byte, r Record) error {
	// Only immediate fields count. Nested environment/endpoint strings cannot
	// impersonate program, domain, or the per-line argument vector.
	lines := strings.Split(string(b), "\n")
	if len(lines) < 2 || lines[0] != service(r)+" = {" {
		return ErrUnverified
	}
	fields := map[string]string{}
	var args []string
	inArgs := false
	for _, line := range lines[1:] {
		if strings.HasPrefix(line, "\t\t") {
			if inArgs {
				// launchctl prints one raw argument per line, without indices.
				// Preserve whitespace inside each argument rather than tokenizing it.
				value := strings.TrimPrefix(line, "\t\t")
				if !cleanValue(value) {
					return ErrUnverified
				}
				args = append(args, value)
			}
			continue
		}
		if line == "\t}" {
			inArgs = false
			continue
		}
		if !strings.HasPrefix(line, "\t") {
			continue
		}
		k, v, ok := strings.Cut(strings.TrimPrefix(line, "\t"), " = ")
		if !ok {
			continue
		}
		if _, exists := fields[k]; exists {
			return ErrUnverified
		}
		fields[k] = v
		if k == "arguments" {
			if v != "{" {
				return ErrUnverified
			}
			inArgs = true
		}
	}
	want := []string{r.Executable, "managed-daemon", "--install-dir", r.Dir}
	if fields["program"] != r.Executable || fields["path"] != definitionPath(r) || fields["type"] != "LaunchAgent" || !strings.HasPrefix(fields["domain"], domain(r)+" [") || len(args) != len(want) {
		return ErrUnverified
	}
	if uid, ok := fields["uid"]; ok && uid != r.UserID {
		return ErrUnverified
	}
	for i := range want {
		if args[i] != want[i] {
			return ErrUnverified
		}
	}
	return nil
}
func verifySystemdRegistration(b []byte, r Record) error {
	m := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return ErrUnverified
		}
		if _, ok := m[k]; ok {
			return ErrUnverified
		}
		m[k] = v
	}
	if m["LoadState"] == "not-found" {
		return errAbsent
	}
	for _, key := range []string{"LoadState", "FragmentPath", "DropInPaths", "User"} {
		if _, ok := m[key]; !ok {
			return ErrUnverified
		}
	}
	for _, key := range []string{"ExecCondition", "ExecStartPre", "ExecStartPost", "ExecReload", "ExecStop", "ExecStopPost", "Environment", "EnvironmentFiles", "RootDirectory", "RootImage"} {
		value, ok := m[key]
		if !ok || value != "" {
			return ErrUnverified
		}
	}
	if m["LoadState"] != "loaded" || m["FragmentPath"] != definitionPath(r) || m["DropInPaths"] != "" || (m["User"] != "" && m["User"] != r.UserID) {
		return ErrUnverified
	}

	return nil
}
func systemdObject(r Record) string {
	var b strings.Builder
	for _, c := range []byte(service(r)) {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			b.WriteByte(c)
		} else {
			b.WriteString("_" + strconv.FormatUint(uint64(c), 16))
		}
	}
	return "/org/freedesktop/systemd1/unit/" + b.String()
}
func verifySystemdExec(b []byte, r Record) error {
	var reply struct {
		Type string              `json:"type"`
		Data [][]json.RawMessage `json:"data"`
	}
	if len(b) >= 65536 || json.Unmarshal(b, &reply) != nil || reply.Type != "a(sasbttttuii)" || len(reply.Data) != 1 || len(reply.Data[0]) != 10 {
		return ErrUnverified
	}
	entry := reply.Data[0]
	var path string
	var argv []string
	var ignore bool
	if json.Unmarshal(entry[0], &path) != nil || json.Unmarshal(entry[1], &argv) != nil || json.Unmarshal(entry[2], &ignore) != nil {
		return ErrUnverified
	}
	want := []string{r.Executable, "managed-daemon", "--install-dir", r.Dir}
	if path != r.Executable || ignore || len(argv) != len(want) {
		return ErrUnverified
	}
	for i := range want {
		if argv[i] != want[i] {
			return ErrUnverified
		}
	}
	return nil
}
func verifyTaskRegistration(b []byte, r Record) error {
	// schtasks may return UTF-16 XML on Windows.
	if len(b) >= 2 && (bytes.Equal(b[:2], []byte{255, 254}) || bytes.Equal(b[:2], []byte{254, 255})) {
		little := b[0] == 255
		if len(b)%2 != 0 {
			return ErrUnverified
		}
		u := []uint16{}
		for i := 2; i < len(b); i += 2 {
			v := uint16(b[i])<<8 | uint16(b[i+1])
			if little {
				v = uint16(b[i+1])<<8 | uint16(b[i])
			}
			u = append(u, v)
		}
		b = []byte(string(utf16.Decode(u)))
	}
	// XML decoders normally accept duplicate scalar elements. A registered task
	// is trusted only when each security-relevant element is unambiguous.
	if e := uniqueTaskFields(b); e != nil {
		return e
	}
	d := xml.NewDecoder(bytes.NewReader(b))
	d.CharsetReader = func(charset string, in io.Reader) (io.Reader, error) {
		if strings.EqualFold(charset, "UTF-16") {
			return in, nil
		}
		return nil, errors.New("unknown XML charset")
	}
	var task struct {
		XMLName    xml.Name `xml:"Task"`
		Principals []struct {
			ID    string `xml:"id,attr"`
			User  string `xml:"UserId"`
			Group string `xml:"GroupId"`
			Logon string `xml:"LogonType"`
			Level string `xml:"RunLevel"`
		} `xml:"Principals>Principal"`
		Actions []struct {
			Context string `xml:"Context,attr"`
			Exec    []struct {
				Command          string
				Arguments        string
				WorkingDirectory string
			} `xml:"Exec"`
			Other []struct{ XMLName xml.Name } `xml:",any"`
		} `xml:"Actions"`
	}
	if d.Decode(&task) != nil {
		return ErrUnverified
	}
	for {
		tok, e := d.Token()
		if e == io.EOF {
			break
		}
		if e != nil {
			return ErrUnverified
		}
		if text, ok := tok.(xml.CharData); !ok || len(bytes.TrimSpace(text)) != 0 {
			return ErrUnverified
		}
	}
	if task.XMLName.Space != "http://schemas.microsoft.com/windows/2004/02/mit/task" || len(task.Principals) != 1 || len(task.Actions) != 1 {
		return ErrUnverified
	}
	p, a := task.Principals[0], task.Actions[0]
	if p.ID != "Owner" || p.User != r.UserID || p.Group != "" || p.Logon != "InteractiveToken" || p.Level != "LeastPrivilege" || a.Context != "Owner" || len(a.Exec) != 1 || len(a.Other) != 0 {
		return ErrUnverified
	}
	x := a.Exec[0]
	if x.Command != r.Executable || x.Arguments != windowsArgs([]string{"managed-daemon", "--install-dir", r.Dir}) || x.WorkingDirectory != "" {
		return ErrUnverified
	}
	return nil
}

func uniqueTaskFields(b []byte) error {
	d := xml.NewDecoder(bytes.NewReader(b))
	d.CharsetReader = func(charset string, in io.Reader) (io.Reader, error) {
		if strings.EqualFold(charset, "UTF-16") {
			return in, nil
		}
		return nil, ErrUnverified
	}
	path := []string{}
	seen := map[string]bool{}
	for {
		token, e := d.Token()
		if e == io.EOF {
			return nil
		}
		if e != nil {
			return ErrUnverified
		}
		switch t := token.(type) {
		case xml.StartElement:
			if t.Name.Space != "http://schemas.microsoft.com/windows/2004/02/mit/task" {
				return ErrUnverified
			}
			path = append(path, t.Name.Local)
			key := strings.Join(path, "/")
			if strings.HasPrefix(key, "Task/Principals") || strings.HasPrefix(key, "Task/Actions") || strings.HasPrefix(key, "Task/Triggers") {
				if seen[key] {
					return ErrUnverified
				}
				seen[key] = true
				attr := map[xml.Name]bool{}
				for _, a := range t.Attr {
					if attr[a.Name] {
						return ErrUnverified
					}
					attr[a.Name] = true
				}
			}
		case xml.EndElement:
			if len(path) == 0 {
				return ErrUnverified
			}
			path = path[:len(path)-1]
		}
	}
}
