// Package capture reads bounded private local transcripts and submits protected
// chunk/session plans through the store's fenced atomic producer transaction.
package capture

import (
	"context"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Telara-Labs/hilo/contract/internal/node/localpolicy"
	"github.com/Telara-Labs/hilo/contract/record"
)

const (
	maxFrame        = 8 << 20
	maxUnit         = 64 << 20
	maxObservations = 4096
	maxText         = 64 << 10
	maxArgs         = 256
	readerVersion   = "native-jsonl-preparation/1"
	localPolicyID   = localpolicy.ID
)

// All errors are fixed codes. Never wrap parser, filesystem, policy, or native
// errors, whose messages can contain a path, transcript, or credential.
func hold(code string) error { return &Error{code: code} }

// Error never includes transcript text, paths, parser errors or secret material.
// cause is the fixed local code behind a store producer refusal, when known.
type Error struct{ code, cause string }

func (e *Error) Error() string { return "capture held: " + e.code }
func Code(err error) string {
	if err == nil {
		return ""
	}
	if e, ok := err.(*Error); ok {
		return e.code
	}
	return "capture_failure"
}

type sourceOccurrence struct{ source, session, owner, machine string }
type gateState struct{ suppressed, ownerBlocked bool }
type preOpenGate func(context.Context, sourceOccurrence) (gateState, error)

type preparationConfig struct {
	root, home, owner, machine string
	enabled                    bool
	policy                     localPolicy
}
type unitLocator struct {
	client, relative, source, session string
	// Resolved by the future trusted runtime from a durable mapping. It is
	// an immutable value, never a mutable map or native content probe.
	mappedSession string
}
type position struct{ line, block, inner int }
type field struct {
	name, text          string
	argument, truncated bool
	nativeKind          string
	fullRedactedBytes   int
}
type preparedObservation struct {
	kind, nativeID, callID string
	position               position
	fields                 []field
	// This reports a literal native flag, never verified execution or success.
	observedError bool
}
type preparedBatch struct {
	occurrence              sourceOccurrence
	client, reader, ruleset string
	// Local file ownership proves permission to read, not native truth. These
	// fixed values cannot be selected by any native JSON field.
	provenance                      string
	observations                    []preparedObservation
	nativeSession, homeRelativeUnit string
}

// localPolicy is an immutable, fixed local ruleset, not a caller-provided
// redaction callback. Other profiles and tenant overlays are unsupported.
type localPolicy struct {
	selected bool
	overlay  localpolicy.Overlay
}

func selectLocalPolicy(profile string, tenantOverlay bool) (localPolicy, error) {
	if profile != "local" || tenantOverlay {
		return localPolicy{}, hold("unsupported_policy")
	}
	return localPolicy{selected: true}, nil
}
func (p localPolicy) text(s string) string           { return p.overlay.Text(s) }
func (p localPolicy) argument(name, s string) string { return p.overlay.Argument(name, s) }

type fullFieldRules interface {
	text(string) string
	argument(string, string) string
}

var safeToken = regexp.MustCompile(`^[A-Za-z0-9_.:/-]{1,200}$`)

func identifier(s string) bool {
	return s != "" && safeToken.MatchString(s) && localpolicy.Text(s) == s
}

func resolve(c preparationConfig, u unitLocator) (string, error) {
	if !supportedClient(u.client) {
		return "", hold("unsupported_client")
	}
	if !record.IsKeyID(c.owner) || !record.IsUUIDv4(c.machine) || !record.IsHex64(u.source) || !record.IsSessionKey(u.session) {
		return "", hold("unresolved_identity")
	}
	if !filepath.IsAbs(c.root) || filepath.Clean(c.root) != c.root || !filepath.IsAbs(c.home) || filepath.Clean(c.home) != c.home || u.relative == "" || filepath.IsAbs(u.relative) || filepath.Clean(u.relative) != u.relative {
		return "", hold("unsafe_path")
	}
	for _, p := range strings.Split(u.relative, string(filepath.Separator)) {
		if p == "" || p == "." || p == ".." {
			return "", hold("unsafe_path")
		}
	}
	if filepath.Ext(u.relative) != ".jsonl" {
		return "", hold("unsupported_format")
	}
	stem := strings.TrimSuffix(filepath.Base(u.relative), ".jsonl")
	native := stem
	if (u.client == "codex" || u.client == "pi") && len(stem) >= 36 {
		native = stem[len(stem)-36:]
	}
	if !record.IsUUID(native) {
		native = u.mappedSession
		if !identifier(native) {
			return "", hold("unresolved_session")
		}
	} else if u.mappedSession != "" && u.mappedSession != native {
		return "", hold("identity_mismatch")
	}
	return native, nil
}

// Source/session keys are pure identities over trusted location/configuration,
// never digests of transcript bytes. The gate must see exactly the identities
// the resolved unit will carry, not independently supplied syntactic tokens.
func occurrence(c preparationConfig, u unitLocator, native string) (sourceOccurrence, error) {
	var empty sourceOccurrence
	rootRel, err := filepath.Rel(c.home, c.root)
	if err != nil || rootRel == ".." || strings.HasPrefix(rootRel, ".."+string(filepath.Separator)) {
		return empty, hold("unsafe_path")
	}
	unit := filepath.ToSlash(filepath.Join(rootRel, u.relative))
	if localpolicy.Text(unit) != unit {
		return empty, hold("unsafe_path")
	}
	kind := record.NativeLocal
	if record.IsUUID(native) {
		kind = record.NativeGlobal
	}
	session, err := record.SessionKey(u.client, "local", kind, native, c.machine)
	if err != nil {
		return empty, hold("unresolved_identity")
	}
	source, err := record.SourceKey(u.client, c.machine, unit)
	if err != nil {
		return empty, hold("unresolved_identity")
	}
	if u.source != source || u.session != session {
		return empty, hold("identity_mismatch")
	}
	return sourceOccurrence{source, session, c.owner, c.machine}, nil
}

func prepare(ctx context.Context, c preparationConfig, u unitLocator, gate preOpenGate) (preparedBatch, error) {
	b, h, err := prepareHeld(ctx, c, u, gate)
	if h != nil {
		h.close()
	}
	return b, err
}

func prepareHeld(ctx context.Context, c preparationConfig, u unitLocator, gate preOpenGate) (preparedBatch, *openedUnitHandle, error) {
	var empty preparedBatch
	if ctx == nil || ctx.Err() != nil {
		return empty, nil, hold("cancelled")
	}
	if !c.enabled {
		return empty, nil, hold("no_capture")
	}
	if !c.policy.selected {
		return empty, nil, hold("unsupported_policy")
	}
	if gate == nil {
		return empty, nil, hold("missing_gate")
	}
	native, err := resolve(c, u)
	if err != nil {
		return empty, nil, err
	}
	occ, err := occurrence(c, u, native)
	if err != nil {
		return empty, nil, err
	}
	state, err := gate(ctx, occ)
	if err != nil {
		return empty, nil, hold("gate_unavailable")
	}
	if state.ownerBlocked {
		return empty, nil, hold("owner_blocked")
	}
	if state.suppressed {
		return empty, nil, hold("suppressed")
	}
	if ctx.Err() != nil {
		return empty, nil, hold("cancelled")
	}
	h, err := openNativeUnit(c.home, c.root, u.relative)
	if err != nil {
		return empty, nil, err
	}
	// A hook can arrive before its client finishes even the current JSON line.
	// Do not decode a live tail and turn an ordinary partial write into refusal.
	// Ordinary preparation callers retain their existing complete-line behavior.
	if _, signal := ctx.Value(signalAdmissionKey{}).(signalAdmission); signal {
		if err := sourceSettlement(h); err != nil {
			h.close()
			return empty, nil, err
		}
	}
	batch := preparedBatch{occurrence: occ, client: u.client, reader: readerVersion, ruleset: localPolicyID, provenance: "untrusted_local_file"}
	batch.nativeSession = native
	batch.homeRelativeUnit, _ = filepath.Rel(c.home, filepath.Join(c.root, u.relative))
	batch.homeRelativeUnit = filepath.ToSlash(batch.homeRelativeUnit)
	tree := piTree{}
	err = frameUnit(ctx, h, func(line int, b []byte) error {
		if err := strictJSON(b); err != nil {
			return err
		}
		var observations []preparedObservation
		var err error
		switch u.client {
		case "claude-code":
			observations, err = decodeClaude(b, line, native)
		case "codex":
			observations, err = decodeCodex(b, line, native)
		case "cursor-agent":
			observations, err = decodeCursor(b, line)
		case "pi":
			if err = tree.add(b, line); err == nil {
				observations, err = decodePi(b, line, native)
			}
		}
		if err != nil {
			return err
		}
		for _, o := range observations {
			if len(batch.observations) >= maxObservations {
				return hold("observation_limit")
			}
			clean, err := redactObservation(o, c.policy)
			if err != nil {
				return err
			}
			batch.observations = append(batch.observations, clean)
		}
		return nil
	})
	if err == nil && u.client == "pi" {
		err = tree.finish(&batch)
	}
	if err != nil {
		h.close()
		return empty, nil, err
	}
	return batch, h, nil
}

// Input fields are complete native values. This function never calls TAP's
// Flatten/ClaudeEventsWith/CodexCall or an assembler/mining projection.
func redactObservation(o preparedObservation, policy fullFieldRules) (preparedObservation, error) {
	if len(o.fields) > maxArgs {
		return preparedObservation{}, hold("field_limit")
	}
	for i, f := range o.fields {
		// Field names may be dynamic argument keys. Never retain a secret name,
		// nor redact an identity/name into a colliding stable identifier.
		if len(f.name) > 200 || policy.text(f.name) != f.name {
			return preparedObservation{}, hold("unsafe_field_name")
		}
		text := ""
		if f.argument {
			text = policy.argument(f.name, f.text)
		} else {
			text = policy.text(f.text)
		}
		o.fields[i].fullRedactedBytes = len(text)
		o.fields[i].text, o.fields[i].truncated = bound(text, maxText)
	}
	return o, nil
}

func bound(s string, cap int) (string, bool) {
	if len(s) <= cap {
		return s, false
	}
	const marker = "\n[...elided...]\n"
	head := (cap - len(marker)) / 2
	tail := cap - len(marker) - head
	for head > 0 && head < len(s) && (s[head]&0xc0) == 0x80 {
		head--
	}
	start := len(s) - tail
	for start < len(s) && (s[start]&0xc0) == 0x80 {
		start++
	}
	return s[:head] + marker + s[start:], true
}
