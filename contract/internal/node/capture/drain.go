package capture

import (
	"context"

	"github.com/Telara-Labs/hilo/contract/internal/node/store"
	"github.com/Telara-Labs/hilo/contract/transport"
)

// GapSignalStore acknowledges a hint whose capture was refused for a reason a
// retry of the same immutable hint cannot change. It must durably retain the
// hint with a spool_done receipt and the fixed refusal code in one transaction,
// without reading, sealing or advancing capture progress.
type GapSignalStore interface {
	SkipSignalWithGap(context.Context, transport.HookSignal, string, string) error
}

// drainClass is the explicit outcome of one spool file in Drain.
type drainClass uint8

const (
	// drainFatal means the store, the spool or the collector's configuration is
	// broken. Only this class may deny the capture proof. It is the default for
	// any code that is not listed below.
	drainFatal drainClass = iota
	// drainPending keeps the file, applies its identity announcement and retries
	// it on a later drain. MCP is unaffected.
	drainPending
	// drainGap durably acknowledges the hint with a gap receipt, then unlinks it
	// and counts it. Capture progress does not move.
	drainGap
	// drainDrop unlinks a hint that is itself not trustworthy, without retaining
	// it, and counts it as dropped. It is never an announcement.
	drainDrop
)

// drainClasses lists every capture and store refusal code Drain can observe.
// A missing code is fatal, so a new code fails closed until it is classified.
var drainClasses = map[string]drainClass{
	// Transcript not settled yet. The transcript is the replay source (07 7.2).
	"source_absent": drainPending, "source_unsettled": drainPending, "partial_line": drainPending,
	"no_observations": drainPending, "source_changed": drainPending, "read_failed": drainPending,
	"stale_progress": drainPending, "capture_txn_expired": drainPending, "transaction_expired": drainPending,
	"authority_changed": drainPending, "invalid_causal_state": drainPending,
	// Authority, randomness or recovery state unavailable: defer capture (07 6.1).
	"owner_blocked": drainPending, "privacy_hold_required": drainPending, "bulk_confirmation_required": drainPending,
	"unauthorized_capture": drainPending, "policy_violation": drainPending, "policy_unavailable": drainPending,
	"key_material": drainPending, "signing_failed": drainPending, "sealing_failed": drainPending,
	"history_incomplete": drainPending, "history_unavailable": drainPending, "baseline_unavailable": drainPending,
	"page_unavailable": drainPending, "not_suppressed": drainPending, "producer_refused": drainPending,

	// Content the reader does not cover or that exceeds a bound: an explicit gap,
	// not a held drain (07 6.1 activity-only gap; 02 1 and 2 typed refusals).
	"native_shape": drainGap, "unsupported_content": drainGap, "unsupported_native_record": drainGap,
	"unsupported_role": drainGap, "unsupported_observation": drainGap, "unsupported_nested_exec": drainGap,
	"observation_shape": drainGap, "argument_type": drainGap, "argument_type_metadata": drainGap,
	"invalid_json": drainGap, "json_depth": drainGap, "frame_limit": drainGap, "unit_limit": drainGap,
	"observation_limit": drainGap, "field_limit": drainGap, "unsafe_field_name": drainGap,
	"event_size": drainGap, "event_payload": drainGap, "duplicate_event": drainGap,
	"duplicate_native_entry": drainGap, "cyclic_native_entries": drainGap, "unsafe_native_id": drainGap,
	"session_mismatch": drainGap, "source_position": drainGap, "source_regression": drainGap,
	"ambiguous_tool_call": drainGap, "ambiguous_native_occurrence": drainGap, "ambiguous_source_baseline": drainGap,
	"plan_limit": drainGap, "ordinal_limit": drainGap, "history_limit": drainGap, "record_invalid": drainGap,
	// Policy refusal, not deferral: relaxation is not capture authority (02 2).
	"no_capture": drainGap, "unsupported_policy": drainGap,

	// The hint itself is untrustworthy: deleted and counted, never retained (07 7.2).
	"invalid_signal": drainDrop, "signal_conflict": drainDrop, "signal_session_mismatch": drainDrop,
	"unsafe_path": drainDrop, "path_depth": drainDrop, "unsupported_format": drainDrop,
	"unresolved_session": drainDrop, "unresolved_identity": drainDrop, "identity_mismatch": drainDrop,
	// A hint path that fails the no-follow and owner checks is not a unit (02 5).
	"unsafe_file": drainDrop, "unsafe_permissions": drainDrop,

	// Broken store, spool or configuration.
	"cancelled": drainFatal, "closed": drainFatal, "outcome_unknown": drainFatal, "store_refused": drainFatal,
	"store_identity": drainFatal, "invalid_config": drainFatal, "unknown_root": drainFatal,
	"unsupported_client": drainFatal, "unsupported_platform": drainFatal, "missing_gate": drainFatal,
	"gate_unavailable": drainFatal, "history_invalid": drainFatal, "page_history": drainFatal,
	"page_history_unavailable": drainFatal, "ruleset_golden": drainFatal, "unsafe_spool": drainFatal,
	"spool_limit": drainFatal, "spool_unlink_failed": drainFatal, "spool_receipt_failed": drainFatal,
	"spool_receipts_unavailable": drainFatal, "spool_admission_failed": drainFatal,
	"spool_observation_unavailable": drainFatal, "spool_gap_failed": drainFatal, "ambiguous_root": drainFatal,
	// Reached only when the backend cannot durably acknowledge a suppressed unit.
	"suppressed": drainFatal,
}

// classify returns the drain class of a capture error. A producer refusal with
// a known local cause is classified by that cause.
func classify(err error) (drainClass, string) {
	code := Code(err)
	if e, ok := err.(*Error); ok && e.code == "producer_refused" && e.cause != "" {
		code = e.cause
	}
	if class, ok := drainClasses[code]; ok {
		return class, code
	}
	return drainFatal, code
}

// classifySpoolStore classifies a store refusal of a spool write. Only a
// refusal of the hint itself is a drop; anything else is fatal under fatal.
func classifySpoolStore(err error, fatal string) (drainClass, error) {
	switch store.Code(err) {
	case "invalid_signal", "signal_conflict":
		return drainDrop, nil
	}
	return drainFatal, hold(fatal)
}
