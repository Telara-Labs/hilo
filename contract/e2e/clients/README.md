# Installed client acceptance harness

This macOS harness uses the real adapter, installer, native keychain custody,
daemon, stdio shim, peer authority, disclosure service and SQLite store. It is
compiled only with `-tags e2e`. The installed executable is the compiled test
driver. It dispatches package APIs and records calls around the real MCP backend.
It does not establish release binary packaging or production CLI dispatch.

Native client runs need operator-supplied authentication. No credential files are
discovered, and no interactive login or browser is opened. An absent
`-e2e-CLIENT-auth` skips that client with an explicit UNVERIFIED message. A failed
client, hook, capture, redaction, read-back or cleanup check fails the test.

## Config isolation and sources

| Client | Existing child config variable | Isolated auth destination | Noninteractive invocation |
| --- | --- | --- | --- |
| Claude Code | `CLAUDE_CONFIG_DIR` | `.claude/.credentials.json` | `claude -p --output-format stream-json --verbose` |
| Codex CLI | `CODEX_HOME` | `.codex/auth.json` | `codex exec --json --skip-git-repo-check --sandbox read-only` |
| Cursor Agent | `CURSOR_CONFIG_DIR` | `.cursor/auth.json` | `cursor-agent --print --output-format stream-json` |
| Pi | `PI_CODING_AGENT_DIR` | `.pi/agent/auth.json` | `pi --print --mode json` |

Paths in the table are relative to a new disposable home. Each child receives an
explicit environment allowlist with disposable HOME, TMPDIR and XDG directories.
Provider credentials and shell startup overrides are not inherited. Auth files
must be canonical absolute paths, regular files, private to the operator, JSON
objects and at most 1 MiB. Copies are exclusive, mode 0600, and deleted with the
temporary root. Operator source files are never modified or deleted.

The config variables and execution modes are grounded in vendor documentation
and the installed Cursor code, checked while authoring this harness. These pages
can change independently of the installed versions.

- [Claude settings locations](https://code.claude.com/docs/en/settings),
  [credential custody](https://code.claude.com/docs/en/authentication) and
  [CLI reference](https://code.claude.com/docs/en/cli-reference) describe the config
  override, file fallback and print mode. The configured directory also changes
  the macOS credential entry name. The harness blocks native keychain services
  for client processes and requires the supplied credentials file. It never runs
  `/login`, `auth login` or `setup-token`. Those flows can involve browser login
  or native custody and are not used as unattended isolated authentication here.
  The docs also describe noninteractive API-key use and long-lived OAuth tokens
  supplied through existing client variables. `setup-token` itself still needs
  browser authorization. This harness deliberately takes a supplied credentials
  JSON file instead of provisioning or inheriting those credentials.
- [Official OpenAI configuration documentation](https://developers.openai.com/codex/config-advanced/)
  defines `CODEX_HOME` and file custody.
  [Noninteractive mode](https://developers.openai.com/codex/noninteractive/)
  defines `exec --json`. The isolated TOML sets
  `cli_auth_credentials_store = "file"`. Non-managed hooks need explicit vendor
  trust, as described in [Hooks](https://learn.chatgpt.com/docs/hooks). The harness
  does not manufacture trust records. Missing trust is a failing hook assertion.
- [Cursor configuration](https://cursor.com/docs/cli/reference/configuration)
  defines `CURSOR_CONFIG_DIR` and
  [parameters](https://cursor.com/docs/cli/reference/parameters) defines print and
  JSON modes. The installed 2026.10.22 bundle's file-auth `getAuthFilePath` uses
  `~/.cursor/auth.json` on macOS. The harness sets both the config variable and
  isolated HOME, and selects the matching `.cursor` directory. Credential refresh
  may fail when native custody is blocked. Such a failure is not a memory pass.
- [Pi configuration](https://github.com/badlogic/pi-mono/blob/main/packages/coding-agent/docs/configuration.md)
  defines `PI_CODING_AGENT_DIR` and `auth.json`.
  [Pi CLI](https://github.com/badlogic/pi-mono/blob/main/packages/coding-agent/docs/cli.md)
  describes print and JSON modes. The adapter's owned extension performs MCP
  registration. The harness does not add a substitute Pi extension if that API
  fails in the installed version.

The requested baseline versions are Claude Code 2.1.304, Codex CLI 0.161.0,
Cursor Agent 2026.10.22 and Pi 1.1.0. They are operator-supplied expectations,
UNVERIFIED until a native run records `--version` under isolation. Optional
`-e2e-CLIENT-bin=/canonical/executable` selects an installed binary when PATH does
not contain it. Optional `-e2e-CLIENT-model=MODEL` selects its model.

## Native custody and process isolation

The driver creates a dedicated encrypted keychain through the same
`SecKeychainCreate` pattern as the vault integration test. The existing exported
`vault.RunHelper` executes native secret operations with that explicit keychain
path over anonymous pipes. Empty keychain selection is refused. No native secret
is stored in an environment variable, argument or plaintext file.

Go cannot put cgo in a `_test.go` file. A minimal C creation/deletion utility is
therefore embedded in the test, compiled with the system clang inside the temp
root, and deleted at cleanup. Its password arrives over stdin. It neither calls
the `security` CLI nor selects the default keychain.
[Apple's private-keychain creation path](https://github.com/apple-oss-distributions/Security/blob/main/OSX/libsecurity_keychain/lib/StorageManager.cpp)
excludes private paths from automatic search-list updates. The fixture uses
`probe.keychain`, never a login or system keychain name. Native behavior on this
Mac remains part of the operator gate.

Native Put requires a stable certificate signature. Compile and sign the test
driver before running it. The harness never performs signing or reads a signing
keychain. Use an operator-provided signing keychain for the preparation step.
Ad hoc signatures and ordinary unsigned `go test` binaries cannot establish
native custody and will fail bootstrap. Never change the login keychain to make
these tests pass.

Every native client launch, including `--version`, uses a mandatory
`/usr/bin/sandbox-exec` profile that denies real-home reads and writes, permits
read access to its resolved installation code directory, and denies keychain service
lookups. For npm installations, the code exception includes the corresponding
`node_modules` tree so package dependencies can load. Writes beneath the harness
root are denied except for the disposable client home, hook spool and hook traces.
The driver, native utility, profile, database and daemon call observations are
protected from client writes. No fallback launch is allowed if the sandbox is unavailable. This
profile is probed before any client launch using disposable read/write canaries
and an explicitly isolated native keychain lookup. A failed probe stops the run.
The probe never attempts access to a real home credential or login keychain.
This enforcement needs native verification on the operator's macOS version. HOME
redirection alone is not treated as keychain isolation.

The installer receives a unique launchd label and disposable Home. Its registered
job exits while a pending marker exists. The manually launched verified image
has a test-only `--manual` flag and a deadline. This avoids simultaneous manager
and manual startup. The pending marker is not a product configuration option.

Cleanup attempts daemon quiescence, process-group termination and reap,
`install.Uninstall` with `disclosure.DeleteInstalledSecret`, dedicated keychain
deletion and recursive temp removal, including partial setup and failed checks.
If native uninstall fails, it also attempts bootout of only this invocation's
unique job and records cleanup FAIL. Cleanup denial is never reported as success.
Go's own process being forcibly killed, an OS crash or an unavailable native
manager cannot be covered by deferred cleanup.

The default deadline is 90 seconds per child, including the manually launched
daemon. `-e2e-child-timeout=180s` allows a longer smoke run, up to 5 minutes per
child. The outer Go test timeout must leave room for four clients and cleanup.
No test runs in parallel. Long Unix socket paths are refused before runtime
state is created. `-e2e-temp-parent=/canonical/private/temp` can select a shorter
existing parent when needed. The full root is resolved with
`filepath.EvalSymlinks` and runtime paths must stay beneath it.

## What each native run proves

1. Execute `clients install` through the installed test driver with explicit
   home, config root and data paths. Merge `manual_merge` snippets only into the
   new isolated files. An existing destination is refused. Pi installs its owned
   extension through the real adapter.
2. Launch session A in a new working directory. Request one task creation with
   a unique nonce and include a synthetic GitHub-token canary in conversation
   text. Record exact requests and responses at the real daemon backend.
3. Require a published Stop/SessionEnd equivalent carrying this client's native
   session identity. Read the real store using a read-only SQLite connection.
   Require live, signature-verified parsed session records for that client and
   identity, referenced transcript
   chunks, redaction epoch/fingerprint and a redacted canary. Task creation by
   itself cannot satisfy session capture.
4. Launch session B as a new process in another fresh working directory. Require
   an observed successful `telara_task_list` request and response containing the
   nonce and typed assistant output that prints it. Echoed prompts, tool
   arguments and failed responses are insufficient.
5. Write a unique mode-0600 JSON receipt to the explicit existing status
   directory, after cleanup. It contains version, isolated paths, phase timings,
   timestamped observed calls, hooks, session record IDs, failure and cleanup
   state. Raw client stdout/stderr and auth sources are not persisted. Observation
   text passes through the real redactor, so sensitive values are masked.

The current daemon has no spool/transcript collector connected. Its real peer
authority refuses a nonempty spool rather than silently ignoring it. The capture
pipeline currently supports only Claude Code and Codex roots. Cursor and Pi full
capture remain unavailable. Codex hook trust and Pi's runtime MCP registration
are additional native gates. This harness intentionally exposes those gaps and
does not install a test collector, delete pending signals or provide mocked
Telara services to make native runs green.

## Run the checks

From the `contract` module, portable fixture checks need no auth or keychain
access. These macOS tests compile the native utility without executing it and
exercise real adapters, hook spooling, decoder capture, SQLite and assertions.
The installed-client tests skip without auth flags.

```sh
GOWORK=off go vet -tags e2e ./e2e/...
GOWORK=off go test -p 1 -tags e2e -count=1 -timeout 300s ./e2e/...
GOWORK=off go test -p 1 -race -tags e2e -count=1 -timeout 300s ./e2e/...
```

Compile the driver once into a disposable operator-selected directory.

```sh
GOWORK=off go test -p 1 -tags e2e -c -o /canonical/private/temp/clients.test ./e2e/clients
```

Before the next command, the operator signs that binary with a stable certificate
using their explicitly supplied signing keychain. Signing is outside the harness.
For example, the operator can run this preparation command with their own paths
and certificate identity.

```sh
/usr/bin/codesign --force --sign 'stable certificate identity' \
  --keychain /canonical/operator-signing.keychain \
  --identifier dev.telara.memory.clients-e2e \
  /canonical/private/temp/clients.test
```

Then exercise the full native node lifecycle without launching any client binary
or supplying provider auth.

```sh
/canonical/private/temp/clients.test \
  -test.run='^TestInstalledClients$' -test.timeout=20m \
  -e2e-dry-run \
  -e2e-results-dir=/canonical/existing/status-directory
```

Dry-run performs real installation, isolated keychain bootstrap, adapter merge,
two synthetic MCP sessions over stdio/IPC, terminal-hook publication and a real
fail-closed check for pending spool. It records
`DRY_RUN_PASS_NATIVE_UNVERIFIED`, never native client PASS. Separately,
`TestCaptureDryRun` exercises the real supported transcript decoders and SQLite
capture against synthetic data in its own store. That explicit pipeline call
does not establish the absent daemon collector. Full native lifecycle dry-run
requires a signed driver and an available native manager/keychain outside the
restricted sandbox.

Supply canonical operator-prepared mode-0600 auth files for native acceptance.
Every client without its auth flag skips.

```sh
/canonical/private/temp/clients.test \
  -test.run='^TestInstalledClients$' -test.timeout=20m \
  -e2e-results-dir=/canonical/existing/status-directory \
  -e2e-claude-auth=/canonical/operator-input/claude.json \
  -e2e-codex-auth=/canonical/operator-input/codex.json \
  -e2e-cursor-auth=/canonical/operator-input/cursor.json \
  -e2e-pi-auth=/canonical/operator-input/pi.json
```

No native clients were launched while authoring the harness. Native execution,
provider auth compatibility, sandbox enforcement, installed custody, launchd
cleanup and full native capture/read-back are UNVERIFIED until the operator runs
the corresponding gate and inspects its receipt.
