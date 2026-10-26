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
	"strings"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	nodesync "github.com/Telara-Labs/telara-memory/contract/internal/node/sync"
	"github.com/Telara-Labs/telara-memory/contract/record"
)

// HostedEnrollmentInput is explicit operator consent using an existing human
// sign-in and owned bootstrap key. It is consumed from stdin, never argv or env.
// Browser signup and device authorization remain separate product surfaces.
type HostedEnrollmentInput struct {
	Server     string   `json:"server"`
	UserToken  string   `json:"user_token"`
	Bootstrap  string   `json:"bootstrap"`
	Consent    bool     `json:"consent"`
	MemoryOnly bool     `json:"memory_only"`
	Ops        []string `json:"ops"`
	Repos      []string `json:"repos"`
	ExpiresAt  int64    `json:"expires_at_unix"`
}

func ParseHostedEnrollment(r io.Reader) (HostedEnrollmentInput, error) {
	var in HostedEnrollmentInput
	raw, err := io.ReadAll(io.LimitReader(r, 65537))
	defer clear(raw)
	if err != nil || len(raw) > 65536 {
		return in, ErrEnrollment
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&in) != nil || d.Decode(new(any)) != io.EOF || in.validate() != nil {
		return HostedEnrollmentInput{}, ErrEnrollment
	}
	return in, nil
}
func (in HostedEnrollmentInput) validate() error {
	u, err := url.Parse(in.Server)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || len(in.Server) > 2048 || !in.Consent || !in.MemoryOnly || in.ExpiresAt <= time.Now().Unix() || len(in.Ops) == 0 || len(in.Ops) > 3 || len(in.Repos) == 0 || len(in.Repos) > 128 {
		return ErrEnrollment
	}
	if len(in.UserToken) == 0 || len(in.UserToken) > 32768 || strings.ContainsAny(in.UserToken, " \t\r\n") || !validRefresh(in.Bootstrap) || len(in.Bootstrap) > 512 {
		return ErrEnrollment
	}
	seen := map[string]bool{}
	for _, op := range in.Ops {
		if seen[op] || op != "push" && op != "pull" && op != "erase" {
			return ErrEnrollment
		}
		seen[op] = true
	}
	if !seen["push"] {
		return ErrEnrollment
	}
	seen = map[string]bool{}
	for _, repo := range in.Repos {
		if !strings.HasPrefix(repo, "r1:") || !record.IsHex64(strings.TrimPrefix(repo, "r1:")) || seen[repo] {
			return ErrEnrollment
		}
		seen[repo] = true
	}
	return nil
}

// EnrollHosted uses a bounded TLS-only, no-redirect exchange. It does not trust
// terminal policy roots or write a credential until existing LoginTLS verifies
// the returned authority with a fresh authenticated device-bound login.
func EnrollHosted(ctx context.Context, dir string, vault SecretVault, roots *x509.CertPool, in HostedEnrollmentInput) (LoginReport, error) {
	defer func() { in.UserToken = ""; in.Bootstrap = "" }()
	if in.validate() != nil {
		return LoginReport{}, ErrEnrollment
	}
	if _, err := CreateKey(ctx, dir, vault); err != nil {
		return LoginReport{}, err
	}
	p, err := LoadProfile(dir)
	if err != nil {
		return LoginReport{}, err
	}
	genesis, err := installedGenesis(ctx, dir, p)
	if err != nil {
		return LoginReport{}, err
	}
	k := VaultKeystore{Vault: vault, Key: p.Credential}
	key, err := k.read(ctx)
	if err != nil {
		return LoginReport{}, ErrCredential
	}
	public, err := nodesync.PublicJWKOf(&key.PublicKey)
	key.D.SetInt64(0)
	if err != nil {
		return LoginReport{}, ErrCredential
	}
	body, err := json.Marshal(struct {
		Consent    bool            `json:"consent"`
		MemoryOnly bool            `json:"memory_only"`
		Bootstrap  string          `json:"bootstrap"`
		Genesis    record.Envelope `json:"genesis"`
		Ops        []string        `json:"ops"`
		Repos      []string        `json:"repos"`
		Origin     string          `json:"origin"`
		ExpiresAt  int64           `json:"expires_at_unix"`
	}{true, true, in.Bootstrap, genesis, in.Ops, in.Repos, "local", in.ExpiresAt})
	if err != nil {
		return LoginReport{}, ErrEnrollment
	}
	defer clear(body)
	target := in.Server + "/v1/memory/enroll"
	proof, err := nodesync.EnrollmentProof(ctx, &vaultSigner{store: k, public: public}, target, in.UserToken, time.Now().Unix())
	if err != nil {
		return LoginReport{}, ErrCredential
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 15 * time.Second, MaxResponseHeaderBytes: 16384, DisableCompression: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return LoginReport{}, ErrEnrollment
	}
	req.Header.Set("Authorization", "Bearer "+in.UserToken)
	req.Header.Set("DPoP", proof)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return LoginReport{}, ErrLoginUnverified
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK || res.Header.Get("Content-Encoding") != "" && res.Header.Get("Content-Encoding") != "identity" {
		return LoginReport{}, ErrLoginUnverified
	}
	doc, err := ParseLogin(res.Body)
	if err != nil {
		return LoginReport{}, ErrLoginUnverified
	}
	defer func() { doc.RefreshToken = "" }()
	if doc.Origin != in.Server || doc.RefreshToken != in.Bootstrap || doc.Grant.GenesisID != p.Genesis || doc.Grant.DeviceID != p.Device || doc.Grant.Origin != "local" || doc.Grant.ExpiresAtUnix != in.ExpiresAt || !sameSelection(doc.Grant.Ops, in.Ops) || !sameSelection(doc.Grant.Repos, in.Repos) {
		return LoginReport{}, ErrLoginUnverified
	}
	return LoginTLS(ctx, dir, vault, roots, doc)
}
func sameSelection(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]bool{}
	for _, v := range a {
		if seen[v] {
			return false
		}
		seen[v] = true
	}
	for _, v := range b {
		if !seen[v] {
			return false
		}
	}
	return true
}
func installedGenesis(ctx context.Context, dir string, p Profile) (record.Envelope, error) {
	st, err := store.Open(ctx, store.Options{Dir: dir, PinnedGenesisID: p.Genesis, LocalMachineID: p.Device})
	if err != nil {
		return record.Envelope{}, err
	}
	defer st.Close()
	snap, err := st.Snapshot(ctx, store.ReadRequest{})
	if err != nil {
		return record.Envelope{}, err
	}
	for _, e := range snap.Entries {
		r, err := record.Parse(e.HeaderJCS, e.BodyJCS, e.AdvisoryID)
		if err != nil {
			continue
		}
		if b, ok := r.Body.(*record.KeyOpBody); ok && b.Op == record.OpGenesis && b.Subject.KeyID == p.Genesis && b.Subject.MachineID == p.Device && e.State == "live" && e.SignatureStatus == "verified" {
			return nodesync.Envelope(e.HeaderJCS, e.BodyJCS, e.Sigs, e.AdvisoryID), nil
		}
	}
	return record.Envelope{}, ErrIdentity
}
