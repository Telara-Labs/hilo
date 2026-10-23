package clients

// CaptureGapState distinguishes user action, absent implementation and missing
// runtime evidence. A manual hook install does not block independent transcript
// collection, and no status here certifies daemon admission or read-back.
type CaptureGapState string

const (
	ManualRequired CaptureGapState = "manual_required"
	Missing        CaptureGapState = "missing"
	Unverified     CaptureGapState = "unverified"
)

type CaptureGapCode string

const (
	SharedMCPMergeRequired    CaptureGapCode = "shared_mcp_merge_required"
	SharedHooksMergeRequired  CaptureGapCode = "shared_hooks_merge_required"
	HookTrustReviewRequired   CaptureGapCode = "hook_trust_review_required"
	ExistingTOMLUnvalidated   CaptureGapCode = "existing_toml_unvalidated"
	NativeLifecycleUnverified CaptureGapCode = "native_lifecycle_dispatch_unverified"
	AssistantDecoderMissing   CaptureGapCode = "assistant_decoder_missing"
	PromptIdentityUnverified  CaptureGapCode = "prompt_identity_refresh_unverified"
	ExtensionReloadRequired   CaptureGapCode = "extension_reload_required"
	NativeAgentEndUnverified  CaptureGapCode = "native_agent_end_unverified"
	ConnectedMCPUnverified    CaptureGapCode = "connected_mcp_calls_unverified"
	CompleteCaptureUnverified CaptureGapCode = "complete_capture_readback_unverified"
	DaemonCaptureUnverified   CaptureGapCode = "daemon_capture_unverified"
	ProductionHookUnverified  CaptureGapCode = "production_hook_wiring_unverified"
)

// CaptureGap is an explicit machine-readable status plus actionable explanation.
// Report.CaptureGaps is additive to the original string Gaps API. These statuses
// describe adapter limitations and evidence boundaries, never infer native proof
// from a config entry, an installed extension or a unit test.
type CaptureGap struct {
	Code   CaptureGapCode
	State  CaptureGapState
	Detail string
}

func captureGaps(c Client) []CaptureGap {
	gaps := []CaptureGap{
		{DaemonCaptureUnverified, Unverified, "Daemon collection and admission have no runtime proof in this adapter. Hooks carry identity hints only."},
		{CompleteCaptureUnverified, Unverified, "Complete native transcript capture and read-back remain unverified."},
		{ProductionHookUnverified, Unverified, "Verify that the installed binary dispatches the hook command. Test-only dispatch does not establish production wiring."},
		{ConnectedMCPUnverified, Unverified, "A config entry or extension registration does not prove connected MCP calls."},
	}
	if c != Pi {
		gaps = append(gaps,
			CaptureGap{SharedMCPMergeRequired, ManualRequired, "Merge the MCP snippet into user settings. Shared settings are never changed by this adapter."},
			CaptureGap{SharedHooksMergeRequired, ManualRequired, "Merge the four lifecycle hook snippets into user settings. Independent transcript collection can operate while hooks remain pending."})
	}
	switch c {
	case Claude:
		gaps = append(gaps, CaptureGap{NativeLifecycleUnverified, Unverified, "Retained isolated evidence covers SessionStart only. Native UserPromptSubmit, Stop and SessionEnd dispatch remain unverified."})
	case Codex:
		gaps = append(gaps,
			CaptureGap{HookTrustReviewRequired, ManualRequired, "Review and trust the exact installed hooks through /hooks. The adapter never bypasses trust."},
			CaptureGap{ExistingTOMLUnvalidated, Unverified, "Existing config.toml is preserved but deliberately not parsed or validated."},
			CaptureGap{NativeLifecycleUnverified, Unverified, "Native trusted-hook dispatch remains unverified. Manual settings do not inherently prevent transcript collection."})
	case Cursor:
		gaps = append(gaps,
			CaptureGap{AssistantDecoderMissing, Missing, "Assistant decoding is incomplete under the supplied capture specification. Activity-only coverage cannot certify full-content capture. Manual installation cannot resolve this gap."},
			CaptureGap{NativeLifecycleUnverified, Unverified, "Native hook dispatch remains unverified."},
			CaptureGap{PromptIdentityUnverified, Unverified, "Native prompt identity refresh remains unverified."})
	case Pi:
		gaps = append(gaps,
			CaptureGap{ExtensionReloadRequired, ManualRequired, "Reload or restart an existing Pi session after changing the owned extension. Shared settings do not need editing."},
			CaptureGap{NativeAgentEndUnverified, Unverified, "Retained isolated evidence covers session_start and session_shutdown only. Native agent_end remains unverified."})
	}
	return gaps
}
