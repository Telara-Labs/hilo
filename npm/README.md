# Hilo

Hilo provides a local memory node for supported AI coding clients. The `hilo` command and the
`telara-memory` compatibility command use the same authenticated native executable and keep the
existing Telara memory profile, configuration, and custody paths.

This directory is a private, versionless staging template. A usable package is created only by
the release staging process after it verifies the signed native release metadata. The template
does not contain a release version or signed release files.

## Requirements

Node.js 22 or newer is required. The package bootstrap currently requires native acceptance on
the target platform. Windows package-cache ACL acceptance is pending, so this package is not
enabled for Windows use.

## Commands

Both command names forward their arguments unchanged to the same native CLI.

```sh
hilo status
hilo clients status
hilo clients install --client claude
```

Client setup is explicit. For Claude Code, Codex CLI, and Cursor, the native command prints
configuration snippets for you to merge. For Pi, it installs the node-owned extension. The
package does not change shared client configuration during installation.

Installing the npm package does not run lifecycle scripts or download a native executable.
On the first explicit invocation of either command, the launcher authenticates and prefetches
the required native executable before running it. This does not install or start the service,
create a profile, provision key custody, or configure a client.
To install the service, pass the native installer a separately verified source binary or a
complete authenticated native release directory.

```sh
hilo install --source /absolute/path/to/verified/telara-memory --sha256 <lowercase-sha256> --version <label>
hilo install --release-dir /absolute/path/to/complete/native-release
```

The existing native install, upgrade, and uninstall safeguards continue to apply. The database,
runtime, install, MCP, and signing-custody names remain compatible with existing Telara memory
profiles.

## Release status

The package remains private and is not a published release. Native platform acceptance and
release review are still required before distribution. The npm template is not a substitute for
those checks.
