package syncnode

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/record"
)

func TestHostedEnrollmentTLSAndConsent(t *testing.T) {
	for _, mode := range []string{"success", "wrong-grant", "redirect", "untrusted-tls"} {
		t.Run(mode, func(t *testing.T) {
			w := newWorld(t)
			w.installKey()
			h := w.hosted
			a := newTenantAuthority(t, 73, h.tenant, h.user)
			_, pol := a.policy(1, "enrollment")
			old := h.srv
			old.Close()
			var doc LoginDocument
			calls := 0
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/memory/enroll" {
					h.serve(rw, r)
					return
				}
				calls++
				if r.Method != "POST" || r.Header.Get("Authorization") != "Bearer synthetic-human-session" {
					t.Error("human authorization binding missing")
					rw.WriteHeader(401)
					return
				}
				if _, err := verifyProof(r.Header.Get("DPoP"), "POST", h.srv.URL+r.URL.Path, "synthetic-human-session", map[string]bool{}); err != nil {
					t.Error("enrollment DPoP invalid")
					rw.WriteHeader(401)
					return
				}
				var request struct {
					Genesis    record.Envelope `json:"genesis"`
					Consent    bool            `json:"consent"`
					MemoryOnly bool            `json:"memory_only"`
				}
				raw, _ := io.ReadAll(io.LimitReader(r.Body, 65537))
				defer clear(raw)
				if json.Unmarshal(raw, &request) != nil || !request.Consent || !request.MemoryOnly || request.Genesis.ID == "" {
					t.Error("explicit consent or installed genesis missing")
					rw.WriteHeader(400)
					return
				}
				if mode == "redirect" {
					rw.Header().Set("Location", h.srv.URL+"/must-not-follow")
					rw.WriteHeader(307)
					return
				}
				reply := doc
				if mode == "wrong-grant" {
					reply.Grant.Repos = []string{"r1:" + strings.Repeat("0", 64)}
				}
				rw.Header().Set("Content-Type", "application/json")
				rw.Header().Set("Cache-Control", "no-store")
				json.NewEncoder(rw).Encode(reply)
			}))
			srv.Config.ErrorLog = log.New(io.Discard, "", 0)
			h.srv = srv
			srv.StartTLS()
			t.Cleanup(srv.Close)
			doc = w.loginDocument(h, a, pol)
			in := HostedEnrollmentInput{Server: srv.URL, UserToken: "synthetic-human-session", Bootstrap: h.bootstrap, Consent: true, MemoryOnly: true, Ops: h.grant.Ops, Repos: h.grant.Repos, ExpiresAt: h.grant.ExpiresAtUnix}
			var roots *x509.CertPool = h.roots()
			if mode == "untrusted-tls" {
				roots = nil
			}
			report, err := EnrollHosted(context.Background(), w.dir, w.vault, roots, in)
			if mode == "success" {
				if err != nil || report.State != "logged_in" {
					t.Fatal("authenticated enrollment", report, err)
				}
			} else if err == nil || !errors.Is(err, ErrLoginUnverified) {
				t.Fatal("unsafe exchange not refused", err)
			}
			if mode != "untrusted-tls" && calls != 1 {
				t.Fatal("redirect or retry sent another enrollment request", calls)
			}
		})
	}
}

func TestHostedEnrollmentInputRefusesImplicitAuthority(t *testing.T) {
	good := HostedEnrollmentInput{Server: "https://example.invalid", UserToken: "synthetic-human", Bootstrap: "telara_mcp_synthetic", Consent: true, MemoryOnly: true, Ops: []string{"push"}, Repos: []string{"r1:" + strings.Repeat("1", 64)}, ExpiresAt: time.Now().Add(time.Hour).Unix()}
	for _, mode := range []string{"consent", "memory-only", "http", "query", "userinfo", "token-newline", "wildcard-repo", "unknown-op", "duplicate", "expired"} {
		in := good
		switch mode {
		case "consent":
			in.Consent = false
		case "memory-only":
			in.MemoryOnly = false
		case "http":
			in.Server = "http://example.invalid"
		case "query":
			in.Server += "?token=bad"
		case "userinfo":
			in.Server = "https://user@example.invalid"
		case "token-newline":
			in.UserToken += "\ninvalid"
		case "wildcard-repo":
			in.Repos = []string{"*"}
		case "unknown-op":
			in.Ops = []string{"admin"}
		case "duplicate":
			in.Ops = []string{"push", "push"}
		case "expired":
			in.ExpiresAt = 1
		}
		raw, _ := json.Marshal(in)
		if _, err := ParseHostedEnrollment(bytes.NewReader(raw)); err == nil {
			t.Fatal("implicit authority accepted", mode)
		}
	}
	raw, _ := json.Marshal(good)
	if _, err := ParseHostedEnrollment(bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseHostedEnrollment(strings.NewReader(string(raw) + ` {}`)); err == nil {
		t.Fatal("trailing document accepted")
	}
}
