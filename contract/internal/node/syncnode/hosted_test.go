package syncnode

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	nodesync "github.com/Telara-Labs/telara-memory/contract/internal/node/sync"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
	"github.com/Telara-Labs/telara-memory/contract/transport"
)

// hosted is an in-process implementation of the hosted wire contract. The
// session mint and POST /v1/memory/import shapes follow the gateway export:
// request {op_id?, envelopes}, op_id ignored, idempotency per signed record id,
// response {"results":[{id,status,hseq,receipt,hosted_task_id}]}, and fixed
// non-200 refusals. HELLO, filtered log and ACK follow contract section 8.2
// because the gateway export does not implement them yet.
type hosted struct {
	t         *testing.T
	mu        sync.Mutex
	srv       *httptest.Server
	authKey   *ecdsa.PrivateKey
	tsk       ed25519.PrivateKey
	device    ed25519.PublicKey
	machine   string
	tenant    string
	user      string
	config    string
	bootstrap string
	grant     nodesync.MemoryGrant
	seen      map[string]bool

	log         []transport.LogItem
	receipts    map[string]record.Receipt
	unavailable map[string]bool
	hseq        int64

	importBodies   [][]byte
	importStatuses []int // consumed per import call; 0 means process normally
	lostReply      int   // process and store, then answer 503 this many times
	badReceipt     int   // answer this many times with a receipt signed by the wrong key
	blockImport    chan struct{}
	helloStatus    int
	pageLimit      int
	logCalls       int
	onLog          func(n int)
	acks           []transport.Ack
	mints          int
	failures       []string

	// Further devices of the same genesis share this one log. Each has its own
	// grant, and its ACKs are recorded per device as the fan-out view.
	peers  map[string]ed25519.PublicKey
	grants map[string]nodesync.MemoryGrant
	acksBy map[string][]transport.Ack
	onAck  func(machine string, a transport.Ack)

	// policyRoot is the tenant policy root this origin's authenticated login
	// response returns; loginDevice, when set, is the device it names instead
	// of the authenticated one.
	policyRoot  *record.Envelope
	loginDevice string
}

func newHosted(t *testing.T, device ed25519.PublicKey, machine string, repos []string) *hosted {
	t.Helper()
	h := &hosted{t: t, device: device, machine: machine, tenant: "tenant-one", user: "user-one", config: "config-one", bootstrap: "telara_mcp_bootstrap_one", seen: map[string]bool{}, receipts: map[string]record.Receipt{}, unavailable: map[string]bool{}, pageLimit: nodesync.MaxPageItems, peers: map[string]ed25519.PublicKey{}, grants: map[string]nodesync.MemoryGrant{}, acksBy: map[string][]transport.Ack{}}
	h.authKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, h.tsk, _ = ed25519.GenerateKey(rand.Reader)
	h.grant = nodesync.MemoryGrant{Ops: []string{"push", "pull"}, Repos: repos, Origin: "local", GenesisID: sig.KeyID(device), DeviceID: machine, ExpiresAtUnix: time.Now().Add(2 * time.Hour).Unix()}
	h.srv = httptest.NewUnstartedServer(http.HandlerFunc(h.serve))
	h.srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	h.srv.StartTLS()
	t.Cleanup(h.srv.Close)
	return h
}

// addDevice serves another enrolled device of the same genesis from this log.
func (h *hosted) addDevice(machine string, pub ed25519.PublicKey) {
	h.mu.Lock()
	defer h.mu.Unlock()
	g := h.grant
	g.DeviceID = machine
	h.peers[machine] = pub
	h.grants[machine] = g
}

// grantFor returns the grant of an enrolled device. The caller holds h.mu or
// owns the fixture exclusively.
func (h *hosted) grantFor(machine string) (nodesync.MemoryGrant, bool) {
	if machine == h.grant.DeviceID {
		return h.grant, true
	}
	g, ok := h.grants[machine]
	return g, ok
}

func (h *hosted) deviceKey(machine string) (ed25519.PublicKey, bool) {
	if machine == h.machine {
		return h.device, true
	}
	k, ok := h.peers[machine]
	return k, ok
}

func (h *hosted) fail(w http.ResponseWriter, status int, reason string) {
	h.failures = append(h.failures, reason)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": reason})
}

func (h *hosted) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/v1/memory/import" {
		h.mu.Lock()
		block := h.blockImport
		h.mu.Unlock()
		if block != nil {
			select {
			case <-block:
			case <-r.Context().Done():
				return
			}
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	w.Header().Set("Date", time.Now().UTC().Format(http.TimeFormat))
	if r.URL.Path == "/v1/mcp/session" {
		h.mint(w, r)
		return
	}
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "DPoP ")
	if !ok {
		h.fail(w, 401, "scheme")
		return
	}
	jkt, err := verifyProof(r.Header.Get("DPoP"), r.Method, h.srv.URL+r.URL.Path, token, h.seen)
	if err != nil {
		h.fail(w, 401, "proof")
		return
	}
	claims, err := verifyES256(token, &h.authKey.PublicKey)
	if err != nil {
		h.fail(w, 401, "token")
		return
	}
	var c struct {
		Exp int64 `json:"exp"`
		Cnf struct {
			JKT string `json:"jkt"`
		} `json:"cnf"`
		Grant struct {
			Device string `json:"device_id"`
		} `json:"memory_grant"`
	}
	if json.Unmarshal(claims, &c) != nil || c.Cnf.JKT != jkt || c.Exp <= time.Now().Unix() {
		h.fail(w, 401, "binding")
		return
	}
	machine := c.Grant.Device
	if _, ok := h.deviceKey(machine); !ok {
		h.fail(w, 403, "device")
		return
	}
	switch {
	case r.Method == "POST" && r.URL.Path == "/v1/memory/import":
		h.importRecords(w, r, machine)
	case r.Method == "GET" && r.URL.Path == "/sync/v1/login":
		h.login(w, machine)
	case r.Method == "POST" && r.URL.Path == "/sync/v1/hello":
		h.hello(w, r, machine)
	case r.Method == "GET" && r.URL.Path == "/sync/v1/log":
		h.page(w, r)
	case r.Method == "POST" && r.URL.Path == "/sync/v1/ack":
		var a transport.Ack
		if decodeStrict(r.Body, &a) != nil {
			h.fail(w, 400, "ack")
			return
		}
		if h.onAck != nil {
			h.onAck(machine, a)
		}
		if machine == h.machine {
			h.acks = append(h.acks, a)
		}
		h.acksBy[machine] = append(h.acksBy[machine], a)
		_, _ = io.WriteString(w, "{}\n")
	default:
		h.fail(w, 404, "route")
	}
}

func (h *hosted) mint(w http.ResponseWriter, r *http.Request) {
	bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || bearer != h.bootstrap {
		h.fail(w, 403, "bootstrap")
		return
	}
	jkt, err := verifyProof(r.Header.Get("DPoP"), r.Method, h.srv.URL+r.URL.Path, bearer, h.seen)
	if err != nil {
		h.fail(w, 401, "proof")
		return
	}
	var body struct {
		Grant struct {
			Ops     []string `json:"ops"`
			Repos   []string `json:"repos"`
			Origin  string   `json:"origin"`
			Genesis string   `json:"genesis_id"`
			Device  string   `json:"device_id"`
			Expiry  string   `json:"expires_at_unix"`
		} `json:"memory_grant"`
	}
	if decodeStrict(r.Body, &body) != nil || body.Grant.Genesis != h.grant.GenesisID || body.Grant.Origin != "local" {
		h.fail(w, 400, "grant")
		return
	}
	grant, ok := h.grantFor(body.Grant.Device)
	if !ok {
		h.fail(w, 400, "grant")
		return
	}
	h.mints++
	now := time.Now().UTC().Truncate(time.Second)
	claims := map[string]any{"exp": now.Add(10 * time.Minute).Unix(), "iat": now.Unix(), "nbf": now.Unix(), "iss": "https://auth.example", "sub": h.user, "aud": []string{"telara-mcp-session"}, "tenant_id": h.tenant, "mcp_config_id": h.config, "cnf": map[string]string{"jkt": jkt}, "memory_grant": grant}
	token, err := signES256(h.authKey, claims)
	if err != nil {
		h.fail(w, 500, "sign")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"session_token": token, "expires_at": claims["exp"]})
}

func (h *hosted) importRecords(w http.ResponseWriter, r *http.Request, machine string) {
	device, _ := h.deviceKey(machine)
	raw, err := io.ReadAll(io.LimitReader(r.Body, nodesync.MaxRequestBytes+1))
	if err != nil || len(raw) > nodesync.MaxRequestBytes {
		h.fail(w, 413, "memory request too large")
		return
	}
	h.importBodies = append(h.importBodies, raw)
	if len(h.importStatuses) > 0 {
		status := h.importStatuses[0]
		h.importStatuses = h.importStatuses[1:]
		if status != 0 {
			h.fail(w, status, "memory admission unavailable; retry")
			return
		}
	}
	var req struct {
		OpID      string            `json:"op_id,omitempty"`
		Envelopes []record.Envelope `json:"envelopes"`
	}
	if json.Unmarshal(raw, &req) != nil || len(req.Envelopes) < 1 || len(req.Envelopes) > 64 {
		h.fail(w, 400, "invalid_import")
		return
	}
	type result struct {
		ID           string          `json:"id"`
		Status       string          `json:"status"`
		HSeq         int64           `json:"hseq,omitempty"`
		Receipt      *record.Receipt `json:"receipt,omitempty"`
		HostedTaskID string          `json:"hosted_task_id,omitempty"`
	}
	var results []result
	for _, e := range req.Envelopes {
		rec, err := decodeEnvelope(e)
		if err != nil {
			h.fail(w, 400, "invalid_import")
			return
		}
		if rec.Header.Type != record.KindTask && rec.Header.Type != record.KindSession || rec.Header.Red.Profile != record.ProfilePushMetadata || rec.Header.Prov != record.ProvDerived {
			h.fail(w, 400, "profile_not_allowed")
			return
		}
		if rec.Header.Author.MachineID != machine {
			h.fail(w, 400, "device_mismatch")
			return
		}
		if grant, _ := h.grantFor(machine); !contains(grant.Repos, rec.Header.Subj.RepoID) {
			h.fail(w, 400, "repo_not_allowed")
			return
		}
		message, _ := sig.RecordMessage(rec.ID)
		if len(e.Sigs) != 1 || sig.Verify(device, sig.CtxRecord, message, e.Sigs[0]) != nil {
			h.fail(w, 400, "invalid_signature")
			return
		}
		if h.unavailable[rec.ID] {
			results = append(results, result{ID: rec.ID, Status: "unavailable"})
			continue
		}
		receipt, exists := h.receipts[rec.ID]
		if !exists {
			h.hseq++
			receipt, _ = sig.SignReceipt(h.tsk, record.Receipt{ID: rec.ID, Tenant: h.tenant, DeviceID: machine, AcceptedAt: time.Now().UnixMilli(), HSeq: h.hseq, Policy: strings.Repeat("c", 64)})
			h.receipts[rec.ID] = receipt
			stored := e
			h.log = append(h.log, transport.LogItem{HSeq: h.hseq, Class: "data", Envelope: stored, Own: true})
		}
		status := "accepted"
		if exists {
			status = "accepted-duplicate"
		}
		copied := receipt
		if h.badReceipt > 0 {
			_, wrong, _ := ed25519.GenerateKey(rand.Reader)
			copied, _ = sig.SignReceipt(wrong, record.Receipt{ID: receipt.ID, Tenant: receipt.Tenant, DeviceID: receipt.DeviceID, AcceptedAt: receipt.AcceptedAt, HSeq: receipt.HSeq, Policy: receipt.Policy})
		}
		results = append(results, result{ID: rec.ID, Status: status, HSeq: receipt.HSeq, Receipt: &copied, HostedTaskID: "mnc2-import-" + rec.ID[:8]})
	}
	if h.badReceipt > 0 {
		h.badReceipt--
	}
	if h.lostReply > 0 {
		h.lostReply--
		h.fail(w, 503, "memory admission unavailable; retry")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
}

// login is the authenticated login response. The contract fixes only that a
// tenant root is pinned from the authenticated, validated TLS login response
// of <node> login; this shape is the minimal one the node needs: the origin,
// the authenticated destination and device, and the policy root.
func (h *hosted) login(w http.ResponseWriter, machine string) {
	if h.policyRoot == nil {
		h.fail(w, 404, "route")
		return
	}
	device := machine
	if h.loginDevice != "" {
		device = h.loginDevice
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(nodesync.LoginReply{Origin: h.srv.URL, Tenant: h.tenant, User: h.user, Config: h.config, DeviceID: device, PolicyRoot: *h.policyRoot})
}

// roots trusts this fixture's TLS certificate only.
func (h *hosted) roots() *x509.CertPool {
	return h.srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
}

func (h *hosted) heads() (ctl, data int64) {
	for _, x := range h.log {
		if x.Class == "control" {
			ctl = max(ctl, x.HSeq)
		} else {
			data = max(data, x.HSeq)
		}
	}
	return
}

func (h *hosted) hello(w http.ResponseWriter, r *http.Request, machine string) {
	if h.helloStatus != 0 {
		h.fail(w, h.helloStatus, "route")
		return
	}
	var in transport.Hello
	if decodeStrict(r.Body, &in) != nil || in.DeviceID != machine || in.Contract != record.ContractVersion {
		h.fail(w, 400, "hello")
		return
	}
	ctl, data := h.heads()
	_ = json.NewEncoder(w).Encode(transport.HelloReply{ContractMin: record.ContractVersion, CtlHead: ctl, DataHead: data, KeysetVersion: 1, ServerTime: time.Now().UnixMilli()})
}

func (h *hosted) page(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	after, e1 := strconv.ParseInt(q.Get("after"), 10, 64)
	through, e2 := strconv.ParseInt(q.Get("through"), 10, 64)
	limit, e3 := strconv.Atoi(q.Get("limit"))
	class := q.Get("class")
	excludeOwn := q.Get("exclude_own") == "true"
	if e1 != nil || e2 != nil || e3 != nil || class == "data" && !excludeOwn || class == "control" && q.Has("exclude_own") {
		h.fail(w, 400, "log query")
		return
	}
	page, err := transport.ScanPage(h.log, class, after, through, min(limit, h.pageLimit), excludeOwn)
	if err != nil {
		h.fail(w, 400, "log scan")
		return
	}
	h.logCalls++
	if h.onLog != nil {
		h.onLog(h.logCalls)
	}
	_ = json.NewEncoder(w).Encode(page)
}

func (h *hosted) addControl(e record.Envelope) int64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.hseq++
	h.log = append(h.log, transport.LogItem{HSeq: h.hseq, Class: "control", Envelope: e})
	return h.hseq
}
func (h *hosted) addData(e record.Envelope) int64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.hseq++
	h.log = append(h.log, transport.LogItem{HSeq: h.hseq, Class: "data", Envelope: e})
	return h.hseq
}

func (h *hosted) imports() [][]byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([][]byte(nil), h.importBodies...)
}
func (h *hosted) ackList() []transport.Ack {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]transport.Ack(nil), h.acks...)
}

func (h *hosted) acksOf(machine string) []transport.Ack {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]transport.Ack(nil), h.acksBy[machine]...)
}

func (h *hosted) serviceKey() ServiceKey {
	pub := h.tsk.Public().(ed25519.PublicKey)
	return ServiceKey{KeyID: sig.KeyID(pub), Public: base64.RawURLEncoding.EncodeToString(pub)}
}

func decodeStrict(r io.Reader, out any) error {
	d := json.NewDecoder(r)
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return fmt.Errorf("trailing")
	}
	return nil
}

// envelopeOf builds a wire envelope with a raw-block zstd body.
func envelopeOf(r *record.Record, sigs []record.Signature) record.Envelope {
	e := record.Envelope{V: record.Version, ID: r.ID, Header: base64.RawURLEncoding.EncodeToString(r.HeaderJCS), Sigs: sigs}
	if len(r.BodyJCS) > 0 {
		e.Body = &record.EnvelopeBody{Codec: "zstd", Bytes: base64.RawURLEncoding.EncodeToString(rawZstdFrame(r.BodyJCS))}
	}
	return e
}

func rawZstdFrame(body []byte) []byte {
	out := []byte{0x28, 0xb5, 0x2f, 0xfd, 0xa0, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(out[5:], uint32(len(body)))
	for len(body) > 0 {
		n := min(len(body), 128<<10)
		last := uint32(0)
		if n == len(body) {
			last = 1
		}
		v := uint32(n)<<3 | last
		out = append(out, byte(v), byte(v>>8), byte(v>>16))
		out = append(out, body[:n]...)
		body = body[n:]
	}
	return out
}

// decodeEnvelope is an independent port of the import envelope decode for raw
// zstd blocks; it does not call the client's restorer.
func decodeEnvelope(e record.Envelope) (*record.Record, error) {
	if e.V != record.Version || e.Receipt != nil || e.Grant != nil || e.Body == nil || e.Body.Codec != "zstd" {
		return nil, fmt.Errorf("envelope")
	}
	header, err := base64.RawURLEncoding.Strict().DecodeString(e.Header)
	if err != nil {
		return nil, err
	}
	compressed, err := base64.RawURLEncoding.Strict().DecodeString(e.Body.Bytes)
	if err != nil || len(compressed) < 12 || !bytes.Equal(compressed[:5], []byte{0x28, 0xb5, 0x2f, 0xfd, 0xa0}) {
		return nil, fmt.Errorf("frame")
	}
	size := int(binary.LittleEndian.Uint32(compressed[5:9]))
	rest := compressed[9:]
	var body []byte
	for {
		if len(rest) < 3 {
			return nil, fmt.Errorf("block")
		}
		v := uint32(rest[0]) | uint32(rest[1])<<8 | uint32(rest[2])<<16
		rest = rest[3:]
		n := int(v >> 3)
		if v&6 != 0 || n > len(rest) {
			return nil, fmt.Errorf("block")
		}
		body = append(body, rest[:n]...)
		rest = rest[n:]
		if v&1 != 0 {
			break
		}
	}
	if len(body) != size || len(rest) != 0 {
		return nil, fmt.Errorf("size")
	}
	return record.Parse(header, body, e.ID)
}

func signES256(key *ecdsa.PrivateKey, claims any) (string, error) {
	h, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT"})
	c, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	msg := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
	d := sha256.Sum256([]byte(msg))
	r, s, err := ecdsa.Sign(rand.Reader, key, d[:])
	if err != nil {
		return "", err
	}
	return msg + "." + base64.RawURLEncoding.EncodeToString(append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)), nil
}

func verifyES256(token string, key *ecdsa.PublicKey) ([]byte, error) {
	p := strings.Split(token, ".")
	if len(p) != 3 {
		return nil, fmt.Errorf("token")
	}
	s, err := base64.RawURLEncoding.DecodeString(p[2])
	if err != nil || len(s) != 64 {
		return nil, fmt.Errorf("token")
	}
	d := sha256.Sum256([]byte(p[0] + "." + p[1]))
	if !ecdsa.Verify(key, d[:], new(big.Int).SetBytes(s[:32]), new(big.Int).SetBytes(s[32:])) {
		return nil, fmt.Errorf("token")
	}
	return base64.RawURLEncoding.DecodeString(p[1])
}

// verifyProof checks an ES256 DPoP proof bound to method, origin+path and the
// credential, with a one-use jti ledger. It returns the key's jkt.
func verifyProof(proof, method, target, credential string, seen map[string]bool) (string, error) {
	bad := fmt.Errorf("proof")
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return "", bad
	}
	headRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", bad
	}
	var head struct {
		Alg string            `json:"alg"`
		Typ string            `json:"typ"`
		JWK map[string]string `json:"jwk"`
	}
	if json.Unmarshal(headRaw, &head) != nil || head.Alg != "ES256" || head.Typ != "dpop+jwt" || head.JWK["kty"] != "EC" || head.JWK["crv"] != "P-256" || head.JWK["d"] != "" {
		return "", bad
	}
	x, e1 := base64.RawURLEncoding.DecodeString(head.JWK["x"])
	y, e2 := base64.RawURLEncoding.DecodeString(head.JWK["y"])
	if e1 != nil || e2 != nil || len(x) != 32 || len(y) != 32 {
		return "", bad
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	raw, err := verifyES256(proof, pub)
	if err != nil {
		return "", bad
	}
	var c struct {
		HTM string `json:"htm"`
		HTU string `json:"htu"`
		ATH string `json:"ath"`
		JTI string `json:"jti"`
		IAT int64  `json:"iat"`
	}
	if json.Unmarshal(raw, &c) != nil {
		return "", bad
	}
	u, err := url.Parse(c.HTU)
	if err != nil || u.RawQuery != "" {
		return "", bad
	}
	ath := sha256.Sum256([]byte(credential))
	if c.HTM != method || c.HTU != target || c.ATH != base64.RawURLEncoding.EncodeToString(ath[:]) || c.JTI == "" || time.Since(time.Unix(c.IAT, 0)) > time.Minute || time.Until(time.Unix(c.IAT, 0)) > 30*time.Second {
		return "", bad
	}
	jkt, err := nodesync.Thumbprint(pub)
	if err != nil || seen[jkt+"\x00"+c.JTI] {
		return "", bad
	}
	seen[jkt+"\x00"+c.JTI] = true
	return jkt, nil
}

var _ = context.Background
