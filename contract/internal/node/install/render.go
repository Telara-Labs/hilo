package install

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

var labelPattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9.-]{0,95}$`)

func xmlText(s string) string { var b bytes.Buffer; xml.EscapeText(&b, []byte(s)); return b.String() }
func cleanValue(s string) bool {
	return s != "" && !strings.ContainsAny(s, "\x00\r\n") && !strings.ContainsFunc(s, func(r rune) bool { return r < 32 || r == 127 })
}
func systemdQuote(s string) string {
	s = strings.ReplaceAll(s, "%", "%%")
	s = strings.ReplaceAll(s, "$", "$$")
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

// Definition renders all platforms on any host, making exact golden review
// possible without mistaking cross-compilation for platform runtime evidence.
func Definition(platform string, r Record) ([]byte, error) {
	if !labelPattern.MatchString(r.Label) || !cleanValue(r.Executable) || !cleanValue(r.Dir) {
		return nil, unsafePath("Definition", r.Dir, "valid label and control-free executable/install paths required", nil)
	}
	args := []string{"managed-daemon", "--install-dir", r.Dir}
	switch platform {
	case "darwin":
		var b strings.Builder
		fmt.Fprintf(&b, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n<key>Label</key><string>%s</string>\n<key>ProgramArguments</key><array>", xmlText(r.Label))
		for _, s := range append([]string{r.Executable}, args...) {
			fmt.Fprintf(&b, "<string>%s</string>", xmlText(s))
		}
		b.WriteString("</array>\n<key>RunAtLoad</key><true/>\n<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>\n<key>ThrottleInterval</key><integer>30</integer>\n<key>ProcessType</key><string>Background</string>\n</dict></plist>\n")
		return []byte(b.String()), nil
	case "linux":
		var command []string
		for _, s := range append([]string{r.Executable}, args...) {
			command = append(command, systemdQuote(s))
		}
		return []byte("[Unit]\nDescription=Local memory node\nStartLimitIntervalSec=180\nStartLimitBurst=3\n\n[Service]\nType=exec\nExecStart=" + strings.Join(command, " ") + "\nRestart=on-failure\nRestartSec=30\nUMask=0077\nTimeoutStopSec=infinity\n\n[Install]\nWantedBy=default.target\n"), nil
	case "windows":
		if !cleanValue(r.UserID) {
			return nil, unsafePath("Definition", r.UserID, "control-free user identity required", nil)
		}
		// InteractiveToken + LeastPrivilege and a specific SID prohibit elevated
		// or other-user logon. Windows command line quoting is separate from XML.
		commandLine := windowsArgs(args)
		return []byte(fmt.Sprintf("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\n<Triggers><LogonTrigger><Enabled>true</Enabled><UserId>%s</UserId></LogonTrigger></Triggers>\n<Principals><Principal id=\"Owner\"><UserId>%s</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>\n<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>false</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><RestartOnFailure><Interval>PT1M</Interval><Count>3</Count></RestartOnFailure></Settings>\n<Actions Context=\"Owner\"><Exec><Command>%s</Command><Arguments>%s</Arguments></Exec></Actions>\n</Task>\n", xmlText(r.UserID), xmlText(r.UserID), xmlText(r.Executable), xmlText(commandLine))), nil
	}
	return nil, ErrUnavailable
}

func windowsArgs(args []string) string {
	var result []string
	for _, s := range args {
		var b strings.Builder
		b.WriteByte('"')
		n := 0
		for _, r := range s {
			if r == '\\' {
				n++
				continue
			}
			if r == '"' {
				b.WriteString(strings.Repeat(`\`, 2*n+1))
			} else {
				b.WriteString(strings.Repeat(`\`, n))
			}
			n = 0
			b.WriteRune(r)
		}
		b.WriteString(strings.Repeat(`\`, 2*n))
		b.WriteByte('"')
		result = append(result, b.String())
	}
	return strings.Join(result, " ")
}

func definitionPath(r Record) string {
	switch r.Platform {
	case "darwin":
		return filepath.Join(r.Home, "Library", "LaunchAgents", r.Label+".plist")
	case "linux":
		return filepath.Join(r.Home, ".config", "systemd", "user", r.Label+".service")
	default:
		return filepath.Join(r.Dir, "task.xml")
	}
}
