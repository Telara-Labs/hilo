// Package clients supplies user-scope client installation plans and local-only
// capture hooks. Install and Uninstall never replace shared client configuration.
// Vendor CLIs have not proved transactional against editors ignoring their lock;
// these surfaces return manual snippets and explicit pending gaps instead.
//
// Pi's documented extensions directory is a separate, node-owned surface. Its
// extension registers the stdio server in memory, without changing mcp.json.
// The extension invokes the same bounded identity-only hook as other clients.
// Uninstall retains a hidden .telara-memory-remove-* recovery inode in the
// extensions directory, without a JavaScript suffix. Existing open descriptors
// may still write to it; it must never be pruned automatically. This is source
// code/installation metadata only, never captured transcript or hook content.
// Report.CaptureGaps distinguishes manual work, missing implementation and
// unverified runtime behavior. Manual hook settings do not block transcript-only
// collection, while a missing assistant decoder does block full-content claims.
//
// CLI wiring is deliberately outside this package. The caller must wire
// `hook --client CLIENT --home HOME --state-dir STATE` to RunHook, always exiting
// successfully and emitting no stdout/stderr from hook failures. Injection is off.
// Hook results describe publication of hints, never capture/admission of content.
package clients
