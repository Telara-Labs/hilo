package syncnode

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/Telara-Labs/hilo/contract/jcs"
	"github.com/Telara-Labs/hilo/contract/record"
)

// HostedEnrollmentInspection describes an authenticated read at one instant.
// It cannot authorize a login and is never accepted as a token or policy root.
type HostedEnrollmentInspection struct {
	Version       int    `json:"version"`
	Origin        string `json:"origin"`
	Tenant        string `json:"tenant"`
	User          string `json:"user"`
	Config        string `json:"config"`
	BootstrapID   string `json:"bootstrap_id"`
	ScopeType     string `json:"scope_type"`
	ScopeID       string `json:"scope_id"`
	UserEpoch     int64  `json:"user_epoch"`
	TenantEpoch   int64  `json:"tenant_epoch"`
	ConfigVersion int64  `json:"config_version"`
}

func (s HostedEnrollmentInspection) validate() error {
	u, err := url.Parse(s.Origin)
	if err != nil || len(s.Origin) > 2048 || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.String() != s.Origin {
		return ErrEnrollment
	}
	if s.Version != 1 || !inspectionTenantID(s.Tenant) || !record.IsUUID(s.User) || !record.IsUUID(s.Config) || !record.IsUUID(s.BootstrapID) || s.ScopeType != "user" || s.ScopeID != s.User || s.UserEpoch < 0 || s.TenantEpoch < 0 || s.ConfigVersion < 1 {
		return ErrEnrollment
	}
	return nil
}

func inspectionTenantID(id string) bool {
	if record.IsUUID(id) {
		return true
	}
	if len(id) != 32 {
		return false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func (s HostedEnrollmentInspection) Matches(expected HostedEnrollmentInspection) bool {
	return s.validate() == nil && expected.validate() == nil && s == expected
}

type HostedBoundEnrollmentInput struct {
	HostedEnrollmentInput
	Expected HostedEnrollmentInspection `json:"expected"`
}

// New bound/inspection inputs reject duplicate and escaped-duplicate members;
// the existing unbound input parser and its compatibility are unchanged.
func parseHostedInspectionJSON(r io.Reader, out any, expected bool) error {
	raw, err := io.ReadAll(io.LimitReader(r, 65537))
	defer clear(raw)
	if err != nil || len(raw) > 65536 {
		return ErrEnrollment
	}
	canonical, err := jcs.Canonicalize(raw)
	defer clear(canonical)
	if err != nil {
		return ErrEnrollment
	}
	fields := append([]string(nil), hostedInspectionInputMembers...)
	if expected {
		fields = append(fields, "expected")
	}
	if exactHostedInspectionObject(raw, fields, expected) != nil {
		return ErrEnrollment
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return ErrEnrollment
	}
	return nil
}

func ParseHostedInspectionInput(r io.Reader) (HostedEnrollmentInput, error) {
	var in HostedEnrollmentInput
	if parseHostedInspectionJSON(r, &in, false) != nil || in.validate() != nil {
		return HostedEnrollmentInput{}, ErrEnrollment
	}
	return in, nil
}

func ParseHostedBoundEnrollment(r io.Reader) (HostedBoundEnrollmentInput, error) {
	var in HostedBoundEnrollmentInput
	if parseHostedInspectionJSON(r, &in, true) != nil || in.HostedEnrollmentInput.validate() != nil || in.Expected.validate() != nil || in.Expected.Origin != in.Server {
		return HostedBoundEnrollmentInput{}, ErrEnrollment
	}
	return in, nil
}

// ParseHostedInspectionResponse is shared by installed-product acceptance and
// the client. It rejects aliases, omitted facts and nulls before struct decoding.
func ParseHostedInspectionResponse(r io.Reader) (HostedEnrollmentInspection, error) {
	raw, err := io.ReadAll(io.LimitReader(r, 8193))
	defer clear(raw)
	if err != nil || len(raw) > 8192 {
		return HostedEnrollmentInspection{}, ErrLoginUnverified
	}
	canonical, err := jcs.Canonicalize(raw)
	defer clear(canonical)
	if err != nil {
		return HostedEnrollmentInspection{}, ErrLoginUnverified
	}
	if exactHostedInspectionObject(raw, hostedInspectionSnapshotMembers, false) != nil {
		return HostedEnrollmentInspection{}, ErrLoginUnverified
	}
	var s HostedEnrollmentInspection
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&s) != nil || d.Decode(new(any)) != io.EOF || s.validate() != nil {
		return HostedEnrollmentInspection{}, ErrLoginUnverified
	}
	return s, nil
}

// InspectHostedEnrollment has no directory, profile or vault parameter. The
// installed command invokes it before resolving any local runtime paths.
func InspectHostedEnrollment(ctx context.Context, roots *x509.CertPool, in HostedEnrollmentInput) (HostedEnrollmentInspection, error) {
	defer func() { in.UserToken = ""; in.Bootstrap = "" }()
	if in.validate() != nil {
		return HostedEnrollmentInspection{}, ErrEnrollment
	}
	body, err := json.Marshal(struct {
		Bootstrap string `json:"bootstrap"`
	}{in.Bootstrap})
	if err != nil {
		return HostedEnrollmentInspection{}, ErrEnrollment
	}
	defer clear(body)
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 15 * time.Second, MaxResponseHeaderBytes: 16384, DisableCompression: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, in.Server+"/v1/memory/enrollment/inspect", bytes.NewReader(body))
	if err != nil {
		return HostedEnrollmentInspection{}, ErrEnrollment
	}
	req.Header.Set("Authorization", "Bearer "+in.UserToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return HostedEnrollmentInspection{}, ErrLoginUnverified
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK || res.Header.Get("Content-Type") != "application/json" || res.Header.Get("Cache-Control") != "no-store" || res.Header.Get("Content-Encoding") != "" && res.Header.Get("Content-Encoding") != "identity" {
		return HostedEnrollmentInspection{}, ErrLoginUnverified
	}
	s, err := ParseHostedInspectionResponse(res.Body)
	if err != nil || s.Origin != in.Server {
		return HostedEnrollmentInspection{}, ErrLoginUnverified
	}
	return s, nil
}

func EnrollHostedBound(ctx context.Context, dir string, vault SecretVault, roots *x509.CertPool, in HostedBoundEnrollmentInput) (LoginReport, error) {
	defer func() { in.UserToken = ""; in.Bootstrap = "" }()
	if in.HostedEnrollmentInput.validate() != nil || in.Expected.validate() != nil || in.Expected.Origin != in.Server {
		return LoginReport{}, ErrEnrollment
	}
	actual, err := InspectHostedEnrollment(ctx, roots, in.HostedEnrollmentInput)
	if err != nil || !actual.Matches(in.Expected) {
		return LoginReport{}, ErrLoginUnverified
	}
	// No CreateKey or other local resource operation precedes this comparison.
	return enrollHosted(ctx, dir, vault, roots, in.HostedEnrollmentInput, &actual)
}

var hostedInspectionInputMembers = []string{"server", "user_token", "bootstrap", "consent", "memory_only", "ops", "repos", "expires_at_unix"}
var hostedInspectionSnapshotMembers = []string{"version", "origin", "tenant", "user", "config", "bootstrap_id", "scope_type", "scope_id", "user_epoch", "tenant_epoch", "config_version"}

// This supplements JCS duplicate detection with exact decoded field spelling
// and complete non-null source facts. Legacy input/login parsers are untouched.
func exactHostedInspectionObject(raw []byte, required []string, expected bool) error {
	canonical, err := jcs.Canonicalize(raw)
	defer clear(canonical)
	if err != nil {
		return ErrEnrollment
	}
	var members map[string]json.RawMessage
	if json.Unmarshal(raw, &members) != nil {
		return ErrEnrollment
	}
	defer func() {
		for _, value := range members {
			clear(value)
		}
	}()
	if len(members) != len(required) {
		return ErrEnrollment
	}
	for _, name := range required {
		value, present := members[name]
		if !present || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return ErrEnrollment
		}
	}
	if expected && exactHostedInspectionObject(members["expected"], hostedInspectionSnapshotMembers, false) != nil {
		return ErrEnrollment
	}
	return nil
}
