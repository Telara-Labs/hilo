# Installed credential custody

The native vault contains the device signing key and installed shim credential.
The local manifest stores only an opaque handle. There is no file fallback.

macOS uses Security.framework through a separate process with a five-second
operation deadline. All item queries request kSecUseAuthenticationUIFail and the
helper disables Keychain interaction. Failure returns keychain_unavailable.
Installation reports the user default Keychain as the selected credential store.
Static builds refuse custody.

Certificate-signed executables use an explicit SecAccess trusted-application ACL
and a designated requirement binding the identifier AND leaf-certificate
fingerprint. Release signing supplies that exact requirement without additional
OR clauses or cdhash constraints. Its identity and identifier stay stable across
signed upgrades.

Ad hoc source builds use Keychain creator-identity trust and an identity-specific
service slot. Creation omits the access attribute to select the native creator
policy. It never supplies an empty trusted-application list or an all-applications
ACL. All queries fail authentication UI. Unsigned/static builds refuse custody.

Before upgrade quiesces the old daemon, the installer stages the authenticated
content-addressed target. A direct lifecycle control request asks the old daemon
to persist a nonsecret owner-only transfer marker, read the secret, and send it
on an anonymous pipe to that exact digest-verified target. The target creates its
own item and reads it back. A mismatched existing item refuses replacement.
Forwarded MCP requests cannot invoke this control. The marker is fsynced before
transfer and after readback.

Old custody remains available until the install receipt switches. The new managed
daemon, under writer admission and before opening storage, verifies its item and
asks the retained verified old executable to delete the exact source slot. A
crash before receipt publication retains old custody; a retry resumes through the
old daemon or retained old image. A crash after publication resumes retirement
from the new daemon. Cleanup is idempotent, including a crash after old deletion.
Stable signed builds sharing one slot never delete that slot during handoff.
Explicit settled uninstall removes pending staging custody and the current item.
A different target is refused while a transfer is pending.

Readback-before-delete necessarily creates a temporary staging item alongside
the old item. The marker selects the active installation and recovery removes
the obsolete item. This is not an atomic physical move between Keychain items.
Both items stay inside the same selected native Keychain; no plaintext recovery
file is written. Round-one creator items can be read from their legacy slot by
their owning image. An older daemon without the handoff entrypoint cannot be
made upgrade-aware retroactively; keep its readable image until migration is
explicitly performed.

Put borrows caller bytes through no-copy CFData during the synchronous native
operation. Get uses a caller-owned mutable Keychain allocation, wipes it with
memset_s, and frees it through the matching Keychain API. Binary helper pipe
buffers are bounded and wiped. OS/framework/transport internals are not claimed
to provide forensic memory erasure.

Windows uses per-user Credential Manager with durable local-machine persistence
and an owner-only native mutex to prevent duplicate replacement. Linux uses the
existing session bus and org.freedesktop.Secret.Service through godbus. No
session-bus autolaunch, interactive unlock or prompt is attempted. Missing, locked
or prompting custody refuses explicitly. Plain Secret Service transport runs only
over the authenticated local session bus; same-user bus inspection is outside the
stated containment boundary.

## Linux collection selection and deletion proof

Selection happens once per profile, before any handle exists, and is persisted
in the owner-only custody record. Later reads, writes and deletes use the
recorded collection path and never resolve an alias again.

1. If the `telara-memory` alias resolves, that dedicated collection is used.
2. Otherwise CreateCollection is asked for it. A reply without a prompt selects
   the new dedicated collection.
3. If the service refuses with a D-Bus error reply, or the creation needs a
   prompt, the default collection (`ReadAlias("default")`) is selected. The
   prompt is dismissed, never shown. GNOME Keyring takes this path, because it
   answers "Only the 'default' alias is supported".
4. A transport failure or deadline refuses, so an unanswered creation is never
   mistaken for a refusal. No default collection also refuses; custody never
   creates one, since that needs a prompt.

The record keeps `alias` (`telara-memory` or `default`; empty in records written
before this path, which always used the dedicated alias) for diagnosis.

A profile holds several independent secrets at once: the installed runtime
authority, the export key, the sync DPoP key and refresh credentials. The
selection record (`custody-location.json`) therefore holds only the collection
choice. Each handle has its own owner-only record, `custody-item-<handle>.json`,
with its own creation generation, item path and state. A handle's record is
written only while that handle's writer lock is held, so operations on
different handles never rewrite each other's evidence. A per-handle record
must name its handle and the selected collection, or custody refuses. Records
written before per-handle records kept their single handle inside the
selection record. That handle stays readable and deletable there; every other
handle gets its own record. A handle present in both places refuses as
ambiguous. An older build cannot see per-handle records and so refuses those
handles.

Keychain and Credential Manager custody are already per handle: the Keychain
account and the Credential Manager target are the handle itself, and the macOS
location record pins only the Keychain path.

Each provisioning generation writes a random 128-bit `creation` value into the
handle's record, in state `creating`, before CreateItem. The item carries the exact
attributes `service`, `handle` and `creation`. After CreateItem the assigned
object path is persisted (`bound`) before SetSecret sends any authority.

- Never adopt. Put refuses with secret_vault_handle_exists if any item with the
  same service and handle exists, whoever made it. Recovery of a lost
  CreateItem reply binds only the single item carrying the recorded `creation`
  value. No item without it is adopted, overwritten or deleted.
- Exact identity. Reads and deletes use the recorded item path. A search result
  at another path refuses as a relocated or ambiguous item.
- Crash recovery. A crash before CreateItem leaves no handle record, or one in
  `creating` with no matching item, so retry or delete proves no creation on
  the same service owner. A handle without a record was never created by this
  profile, so any item carrying its handle is refused, never deleted. A lost CreateItem reply is resolved by the `creation` attribute. A lost
  SetSecret reply leaves `bound` with the exact path. After a service or bus
  restart, absence never proves deletion or no creation, and cleanup refuses.
- Deletion proof. Absence of the recorded item needs three observations of the
  same live collection, on the recorded service owner. The exact attribute search
  is empty. The collection's `Items` property is readable and does not list the
  recorded path. GetSecret on the recorded path returns an object-missing error.
  GNOME reports a missing path as `org.freedesktop.DBus.Error.UnknownMethod`
  ("Object does not exist at path"). A live object without the method returns
  the same name, so UnknownMethod is accepted only with the other two
  observations. UnknownObject and NoSuchObject get no weaker treatment. Any
  failed observation refuses and leaves the record unchanged.

Trade-offs of the default collection.

- Isolation. The Secret Service has no per-application access control. Any
  same-user client on the session bus can read any item in an unlocked
  collection, whichever collection holds it. The dedicated collection therefore
  never isolated access; it separated names. In the default collection, the
  item is separated by its exact attributes, the 128-bit random handle and the
  creation value. A generic client that searches or clears by its own
  attributes does not match it. A user who deletes it by hand in a keyring
  manager removes custody; the next read reports the handle missing or refuses.
- Lock scope. The item locks and unlocks with the login keyring, rather than
  under a separate collection policy. A locked default collection refuses;
  nothing unlocks it.
- Visibility. The item is listed with the user's other login secrets, under the
  label "Telara Memory runtime authority".
- Compatibility. Records written before this change stay readable. A legacy
  `creating` record has no creation value, so it refuses instead of guessing.
  An older build rejects a record with the new fields, and so fails closed.

Installation explicitly grants the registered local shim read access to local
repositories through search, prime and explicit retrieval, plus task create,
checkpoint, pause and complete, including unscoped tasks. Hook injection remains
off. These grants belong to the installed credential, never the hello client
name. No daemon opening or client hello creates a registration or widens a grant.

Installation holds writer admission across provisioning. An owner-only pending
record stores an opaque recovery handle before a key enters native custody. The
complete marker remains durable until first daemon opening transitions it to
admitted under db.lock, before any backend open. Provisioning refuses startup.
An explicit install retry may discard only never-admitted partial bootstrap.
Never-started uninstall deletes native keys under db.lock without a clean-close
receipt. Admitted profiles require normal daemon settlement. Uninstall retains
database files. Windows markers use DACL checks, reparse refusal and write-through
MoveFileEx publication after a writable file flush, rather than mode-bit checks
or a read-only directory flush.

Peer lifetime binding must run before reading hello and remain held through all
requests and proof creation. Darwin uses LOCAL_PEERTOKEN and checks running signed
code against the receipt image. Unsigned Darwin images refuse authorization.
Linux pins SO_PEERCRED with SO_PEERPIDFD and the running executable descriptor.
Kernels without SO_PEERPIDFD explicitly refuse installed authorization. Windows
pins the named pipe client's process handle. PID, image and lifetime checks are
repeated around capture drain and native secret retrieval before proof creation. Same-user injection and transferred IPC handles
are outside containment. No claim is made that image checks detect injected code.

Pending capture signals require synchronous drain before disclosure. Until the
capture consumer is connected, a nonempty or unsafe spool refuses authority.
That refusal must not be reported as successful capture.

Native Keychain tests use a separate encrypted temporary Keychain. A temporary
HOME alone does not isolate the login Keychain. The ad hoc two-build test builds
different executables with -ldflags -X and checks retained-profile identity,
failed target readback, interrupted transfer/retry and idempotent source cleanup.
Its receipt publication fixture does not prove service-manager replacement. The
signed two-build test additionally requires custody-signing-identity. A skipped
test is not upgrade acceptance. Native Windows and Linux runtime tests are
separate from cross-compilation.

Linux private-bus tests run a Go Secret Service double on a real dbus-daemon.
Each crash and identity fixture runs twice: against a service that supports the
dedicated alias, and in a GNOME mode that refuses non-default aliases and
answers UnknownMethod for deleted paths. The double is not GNOME Keyring;
`TestSecretServiceNativeLifecycle` and `TestSecretServiceNativeForeignItemRefused`
run against the real service on the session bus.
