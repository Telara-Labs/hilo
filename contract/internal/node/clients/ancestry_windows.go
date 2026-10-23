package clients

import (
	"errors"
	"unsafe"

	"github.com/Telara-Labs/telara-memory/contract/transport"
	"golang.org/x/sys/windows"
)

func ancestry(pid int) ([]transport.Proc, error) {
	snapshot, e := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if e != nil {
		return nil, errors.New("ancestry_unavailable")
	}
	defer windows.CloseHandle(snapshot)
	parents := map[uint32]windows.ProcessEntry32{}
	p := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	for e = windows.Process32First(snapshot, &p); e == nil; e = windows.Process32Next(snapshot, &p) {
		parents[p.ProcessID] = p
	}
	if !errors.Is(e, windows.ERROR_NO_MORE_FILES) {
		return nil, errors.New("ancestry_unavailable")
	}
	var out []transport.Proc
	for len(out) < 6 && pid > 0 {
		p, ok := parents[uint32(pid)]
		if !ok {
			return out, errors.New("ancestry_unavailable")
		}
		h, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
		if e != nil {
			return out, errors.New("ancestry_unavailable")
		}
		var created, exit, kernel, user windows.Filetime
		e = windows.GetProcessTimes(h, &created, &exit, &kernel, &user)
		windows.CloseHandle(h)
		ms := created.Nanoseconds() / 1000000
		if e != nil || ms <= 0 {
			return out, errors.New("ancestry_unavailable")
		}
		out = append(out, transport.Proc{PID: pid, StartMS: ms, Argv0: processName(windows.UTF16ToString(p.ExeFile[:]))})
		if p.ParentProcessID == uint32(pid) {
			break
		}
		pid = int(p.ParentProcessID)
	}
	return out, nil
}
