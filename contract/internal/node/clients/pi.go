package clients

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

const extensionName = "telara-memory.js"
const receiptName = ".telara-memory.receipt.json"

// Native JS, no npm dependency and no shell. Accessors are documented Pi APIs.
// Event bodies never enter the child input. The child owns redaction/spooling.
func piExtension(o Options) string {
	args, _ := json.Marshal(hookArgs(o))
	mcp, _ := json.Marshal(map[string]any{"command": o.Executable, "args": shimArgs(o)})
	return `// Owned local memory adapter. No context injection or network operations.
import { spawn } from "node:child_process";
export default function (pi) {
  if (typeof pi.registerMcpServer === "function") {
    pi.registerMcpServer("telara-memory", ` + string(mcp) + `);
  }
  for (const event of ["session_start", "agent_end", "session_shutdown"]) {
    pi.on(event, async (_event, ctx) => {
      try {
        const payload = JSON.stringify({ hook_event_name: event,
          session_id: ctx.sessionManager.getSessionId(),
          transcript_path: ctx.sessionManager.getSessionFile() || "", cwd: ctx.cwd });
        await new Promise((resolve) => {
          let child;
          const finish = () => { clearTimeout(deadline); resolve(); };
          // The promise deadline does not depend on error/close or SIGTERM.
          const deadline = setTimeout(() => {
            resolve();
            try { child?.kill("SIGKILL"); } catch {}
          }, 200);
          try {
            child = spawn(` + quoted(o.Executable) + `, ` + string(args) + `, {
              shell: false, windowsHide: true, timeout: 200,
              stdio: ["pipe", "ignore", "ignore"] });
            child.once("error", finish); child.once("close", finish);
            child.stdin.on("error", () => {}); child.stdin.end(payload);
          } catch {
            finish();
            try { child?.kill("SIGKILL"); } catch {}
          }
        });
      } catch { /* Capture is advisory. Never change the client result. */ }
    });
  }
}
`
}

type piReceipt struct {
	Version int    `json:"version"`
	Digest  string `json:"digest"`
}

func digest(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func readReceipt(d *directory) (*piReceipt, error) {
	b, e := d.read(receiptName, 1024)
	if e != nil {
		return nil, e
	}
	if !validObject(b) {
		return nil, unsafePath("readReceipt", receiptName, "receipt must be a strict JSON object", nil)
	}
	var r piReceipt
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if dec.Decode(&r) != nil || r.Version != 1 || len(r.Digest) != 64 {
		return nil, unsafePath("readReceipt", receiptName, "receipt schema/version/digest length invalid", nil)
	}
	if _, e = hex.DecodeString(r.Digest); e != nil {
		return nil, unsafePath("readReceipt", receiptName, "digest must be hexadecimal", e)
	}
	return &r, nil
}

func installPi(ctx context.Context, o Options, l Location) error {
	d, e := openDir(filepath.Dir(l.Extension), true, true)
	if e != nil {
		return e
	}
	defer d.close()
	unlock, e := d.lock()
	if e != nil {
		return e
	}
	defer unlock()
	want := []byte(piExtension(o))
	r, re := readReceipt(d)
	prior, pe := d.read(extensionName, 1<<20)
	if re == nil {
		if r.Digest != digest(want) {
			return ErrConflict
		}
		if pe == nil {
			if !bytes.Equal(prior, want) {
				return ErrConflict
			}
			return nil
		}
		if !errors.Is(pe, os.ErrNotExist) {
			return pe
		}
	} else {
		if !errors.Is(re, os.ErrNotExist) {
			return re
		}
		if pe == nil {
			return ErrConflict
		}
		if !errors.Is(pe, os.ErrNotExist) {
			return pe
		}
		b, _ := json.Marshal(piReceipt{1, digest(want)})
		if e = publishOwned(d, receiptName, b); e != nil {
			return e
		}
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	// Receipt precedes extension. A crash can resume an absent extension safely.
	return publishOwned(d, extensionName, want)
}

func publishOwned(d *directory, name string, b []byte) error {
	// Separate tmp name then no-replace rename. No incomplete extension loads.
	tmp, e := ulid()
	if e != nil {
		return e
	}
	tmp = ".telara-memory-" + tmp
	if e = d.create(tmp, b); e != nil {
		return e
	}
	defer d.remove(tmp)
	if e = renameOwned(d, tmp, name); e != nil {
		return e
	}
	if e = d.sync(); e != nil {
		return e
	}
	got, e := d.read(name, 1<<20)
	if e != nil || !bytes.Equal(got, b) {
		return ErrConflict
	}
	return nil
}

func uninstallPi(ctx context.Context, o Options, l Location) error {
	d, e := openDir(filepath.Dir(l.Extension), false, true)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	defer d.close()
	unlock, e := d.lock()
	if e != nil {
		return e
	}
	defer unlock()
	r, e := readReceipt(d)
	if errors.Is(e, os.ErrNotExist) {
		_, e = d.read(extensionName, 1<<20)
		if errors.Is(e, os.ErrNotExist) {
			return nil
		}
		return ErrConflict
	}
	if e != nil {
		return e
	}
	b, e := d.read(extensionName, 1<<20)
	if e == nil {
		if digest(b) != r.Digest {
			return ErrConflict
		}
		if e = ctx.Err(); e != nil {
			return e
		}
		if e = removeOwned(d, extensionName, r.Digest); e != nil {
			return e
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if e = d.remove(receiptName); e != nil {
		return e
	}
	return d.sync()
}

func piStatus(o Options, l Location, r Report) (Report, error) {
	d, e := openDir(filepath.Dir(l.Extension), false, true)
	if errors.Is(e, os.ErrNotExist) {
		return r, nil
	}
	if e != nil {
		return r, e
	}
	defer d.close()
	receipt, e := readReceipt(d)
	if errors.Is(e, os.ErrNotExist) {
		return r, nil
	}
	if e != nil {
		return r, e
	}
	b, e := d.read(extensionName, 1<<20)
	if errors.Is(e, os.ErrNotExist) {
		r.Gaps = append(r.Gaps, "extension_install_interrupted")
		return r, nil
	}
	if e != nil {
		return r, e
	}
	if digest(b) != receipt.Digest {
		return r, ErrConflict
	}
	r.MCP = "extension_installed_registration_unverified"
	r.Capture = "extension_installed_dispatch_unverified"
	return r, nil
}

// Park the exact directory entry under a non-extension name and verify it.
// Never unlink the parked inode, even after a matching checksum. An editor may
// still hold a writable descriptor and change it after verification. The recovery
// copy preserves those writes and is deliberately never pruned automatically.
// Mismatches restore without overwrite; a conflicting replacement retains both.
func removeOwned(d *directory, name, want string) error {
	label, e := ulid()
	if e != nil {
		return e
	}
	parked := ".telara-memory-remove-" + label
	if e = renameOwned(d, name, parked); e != nil {
		return e
	}
	b, e := d.read(parked, 1<<20)
	if e != nil || digest(b) != want {
		_ = renameOwned(d, parked, name)
		return ErrConflict
	}
	return d.sync()
}
