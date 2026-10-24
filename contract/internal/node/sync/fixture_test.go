package sync

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
)

const device = "11111111-1111-4111-8111-111111111111"

var repo = "r1:" + strings.Repeat("a", 64)

type fakeOutbox struct {
	mu                                       sync.Mutex
	op                                       *Operation
	authorized                               bool
	authCalls, completes, logouts            int
	nextErr, authErr, completeErr, logoutErr error
	beforeAuth                               func()
	ack                                      Acknowledgment
	retries                                  []Retry
	retryErr                                 error
	// Pull cursors are deliberately independent of completion receipts.
	ctlCursor, dataCursor int64
}

func (o *fakeOutbox) Next(_ context.Context, _ Scope, l Limits) (*Operation, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if l != (Limits{64, 4 << 20, 4 << 20}) {
		return nil, ErrInvalid
	}
	return o.op, o.nextErr
}
func (o *fakeOutbox) Authorize(_ context.Context, _ Scope, id, digest string) (bool, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.authCalls++
	if o.beforeAuth != nil {
		o.beforeAuth()
	}
	if o.op == nil || id != o.op.id || digest != o.op.digest {
		return false, ErrInvalid
	}
	return o.authorized, o.authErr
}
func (o *fakeOutbox) Complete(_ context.Context, _ Scope, a Acknowledgment) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.completeErr != nil {
		return o.completeErr
	}
	if o.op == nil || o.op.id != a.OpID || o.op.digest != a.Digest {
		return ErrInvalid
	}
	o.completes++
	o.ack = a
	o.op = nil
	return nil
}
func (o *fakeOutbox) Retry(_ context.Context, _ Scope, r Retry) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.retryErr != nil {
		return o.retryErr
	}
	if o.op == nil || o.op.id != r.OpID || o.op.digest != r.Digest {
		return ErrInvalid
	}
	o.retries = append(o.retries, r)
	return nil
}
func (o *fakeOutbox) Logout(_ context.Context, _ Scope) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.logouts++
	o.op = nil
	return o.logoutErr
}

// Private test keys stay in this fake backend, never in returned Credentials.
type fixtureCredentials struct {
	Refresh string
	DPoP    *ecdsa.PrivateKey
}

type fakeKeystore struct {
	mu             sync.Mutex
	tenants        map[string]fixtureCredentials
	err, deleteErr error
	deleted        []string
	beforeLoad     func()
	beforeSign     func()
}

func (k *fakeKeystore) Load(_ context.Context, s Scope) (Credentials, error) {
	if k.beforeLoad != nil {
		k.beforeLoad()
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.err != nil {
		return Credentials{}, k.err
	}
	v, ok := k.tenants[s.Tenant]
	if !ok {
		return Credentials{}, ErrKeystoreUnavailable
	}
	j, err := jwk(&v.DPoP.PublicKey)
	if err != nil {
		return Credentials{}, err
	}
	return Credentials{v.Refresh, &fakeSigner{k, s, j}}, nil
}
func (k *fakeKeystore) DeleteTenant(_ context.Context, s Scope) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.deleted = append(k.deleted, s.Tenant)
	if k.deleteErr != nil {
		return k.deleteErr
	}
	delete(k.tenants, s.Tenant)
	return nil
}

// The handle retains only a tenant reference and public identity. Every signing
// operation goes back into the store, so deletion/rotation revokes old handles.
type fakeSigner struct {
	store  *fakeKeystore
	scope  Scope
	public PublicJWK
}

func (s *fakeSigner) PublicJWK() PublicJWK { return s.public }
func (s *fakeSigner) Sign(ctx context.Context, digest []byte) ([]byte, error) {
	if s.store.beforeSign != nil {
		s.store.beforeSign()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	v, ok := s.store.tenants[s.scope.Tenant]
	if !ok || s.store.err != nil {
		return nil, ErrKeystoreUnavailable
	}
	j, err := jwk(&v.DPoP.PublicKey)
	if err != nil || j != s.public || len(digest) != 32 {
		return nil, ErrKeystoreUnavailable
	}
	r, v2, err := ecdsa.Sign(rand.Reader, v.DPoP, digest)
	if err != nil {
		return nil, err
	}
	return append(r.FillBytes(make([]byte, 32)), v2.FillBytes(make([]byte, 32))...), nil
}

// Fixture JWT signing is deliberately test-only. Production only sees Sign.
func signJWT(key *ecdsa.PrivateKey, header, claims any) (string, error) {
	if key == nil || key.D == nil || key.D.Sign() <= 0 || key.D.Cmp(elliptic.P256().Params().N) >= 0 {
		return "", ErrToken
	}
	if _, err := jwk(&key.PublicKey); err != nil {
		return "", err
	}
	x, y := key.Curve.ScalarBaseMult(key.D.Bytes())
	if x.Cmp(key.X) != 0 || y.Cmp(key.Y) != 0 {
		return "", ErrToken
	}
	h, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	c, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	message := b64.EncodeToString(h) + "." + b64.EncodeToString(c)
	digest := sha256.Sum256([]byte(message))
	r, v, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return "", err
	}
	signature := append(r.FillBytes(make([]byte, 32)), v.FillBytes(make([]byte, 32))...)
	return message + "." + b64.EncodeToString(signature), nil
}

type fakeKeys struct {
	state *sig.State
	err   error
}

func (k *fakeKeys) State(context.Context) (*sig.State, error) { return k.state, k.err }

type fixture struct {
	t                      *testing.T
	mu                     sync.Mutex
	server                 *httptest.Server
	client                 *Client
	outbox                 *fakeOutbox
	keystore               *fakeKeystore
	keys                   *fakeKeys
	recordKey, receiptKey  ed25519.PrivateKey
	authKey, dpopKey       *ecdsa.PrivateKey
	grant                  MemoryGrant
	scope                  Scope
	seen                   map[string]bool
	saved                  map[string]record.Receipt
	mintCount, pushCount   int
	requests               [][]byte
	proofs                 []string
	tokens                 []string
	statuses, mintStatuses []int
	retryAfter             string
	response               func([]Result) []Result
	claims                 func(map[string]any)
	mintResponse           func(map[string]any)
	dateOffset             time.Duration
	redirect               string
	handlerErr             error
}

func newFixture(t *testing.T, n int) *fixture {
	t.Helper()
	f := &fixture{t: t, seen: map[string]bool{}, saved: map[string]record.Receipt{}}
	_, f.recordKey, _ = ed25519.GenerateKey(rand.Reader)
	_, f.receiptKey, _ = ed25519.GenerateKey(rand.Reader)
	f.authKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f.dpopKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f.scope = Scope{Tenant: "tenant-one", User: "user-one", Config: "config-one", Genesis: sig.KeyID(f.recordKey.Public().(ed25519.PublicKey)), Device: device}
	f.grant = MemoryGrant{Ops: []string{"push", "erase"}, Repos: []string{repo}, Origin: "local", GenesisID: f.scope.Genesis, DeviceID: device, ExpiresAtUnix: time.Now().Add(time.Hour).Unix()}
	f.keystore = &fakeKeystore{tenants: map[string]fixtureCredentials{f.scope.Tenant: {"telara_mcp_node_bootstrap", f.dpopKey}, "tenant-two": {"telara_mcp_other", f.dpopKey}}}
	key := &sig.Key{KeyID: sig.KeyID(f.receiptKey.Public().(ed25519.PublicKey)), Pub: f.receiptKey.Public().(ed25519.PublicKey), Role: record.RoleService, Tenant: f.scope.Tenant, Status: sig.KeyActive}
	f.keys = &fakeKeys{state: &sig.State{Genesis: f.scope.Genesis, Keys: map[string]*sig.Key{record.H("authority", string(record.RoleService), f.scope.Tenant, key.KeyID): key}}}
	f.outbox = &fakeOutbox{authorized: true, ctlCursor: 2, dataCursor: 3}
	if n > 0 {
		var records []SignedRecord
		for i := 0; i < n; i++ {
			records = append(records, f.signed(t, i))
		}
		var err error
		f.outbox.op, err = NewOperation("persistent-operation-1", records)
		if err != nil {
			t.Fatal(err)
		}
	}
	f.server = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	f.server.Config.ErrorLog = log.New(io.Discard, "", 0)
	f.server.StartTLS()
	t.Cleanup(f.server.Close)
	f.scope.Origin = f.server.URL
	cfg := Config{Scope: f.scope, Grant: f.grant, Keystore: f.keystore, Outbox: f.outbox, Keys: f.keys, AuthKey: &f.authKey.PublicKey, AuthIssuer: "https://auth.example", TLSRoots: f.server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs}
	var err error
	f.client, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.client.wait = func(context.Context, time.Duration) error { return nil }
	t.Cleanup(f.client.http.CloseIdleConnections)
	return f
}
func (f *fixture) signed(t *testing.T, i int) SignedRecord {
	t.Helper()
	task := fmt.Sprintf("22222222-2222-4222-8222-%012d", i)
	h := record.Header{Type: record.KindTask, LID: record.TaskLID(record.Owner(record.RoleDevice, f.scope.Genesis, ""), task), Author: record.Author{MachineID: device, KeyID: sig.KeyID(f.recordKey.Public().(ed25519.PublicKey))}, At: 1761150000456, Prov: record.ProvDerived, Subj: record.Subject{TaskID: task, RepoID: repo}, Red: record.Redact{Profile: record.ProfilePushMetadata, Epoch: 7, Fingerprint: strings.Repeat("a", 64)}, Links: record.Links{Origin: strings.Repeat("b", 64)}}
	r, err := record.Build(h, &record.TaskMetaBody{Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	s, err := sig.SignRecord(f.recordKey, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	return SignedRecord{r, []record.Signature{s}}
}
func (f *fixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fail := func(err error) { f.handlerErr = err; http.Error(w, "fixture proof rejected", 401) }
	if r.Method != "POST" {
		fail(fmt.Errorf("method"))
		return
	}
	mint := r.URL.Path == "/v1/mcp/session"
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "DPoP ")
	if mint {
		token = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token != "telara_mcp_node_bootstrap" {
			fail(fmt.Errorf("bootstrap"))
			return
		}
	} else if !strings.HasPrefix(r.Header.Get("Authorization"), "DPoP ") {
		fail(fmt.Errorf("scheme"))
		return
	}
	jkt, err := fixtureProof(r.Header.Get("DPoP"), r.Method, f.server.URL+r.URL.Path, token, time.Now().Add(f.dateOffset), f.seen)
	if err != nil {
		fail(err)
		return
	}
	if !mint {
		raw, err := verifyJWT(token, &f.authKey.PublicKey)
		if err != nil {
			fail(err)
			return
		}
		var claims tokenClaims
		if json.Unmarshal(raw, &claims) != nil || claims.Cnf.JKT != jkt || claims.Exp <= time.Now().Add(f.dateOffset).Unix() {
			fail(fmt.Errorf("token binding or expiry"))
			return
		}
	}
	if mint {
		f.mintCount++
		var b struct {
			Grant struct {
				Ops, Repos []string
				Origin     string `json:"origin"`
				Genesis    string `json:"genesis_id"`
				Device     string `json:"device_id"`
				Exp        string `json:"expires_at_unix"`
			} `json:"memory_grant"`
		}
		data, _ := io.ReadAll(r.Body)
		if json.Unmarshal(data, &b) != nil || b.Grant.Genesis != f.scope.Genesis || b.Grant.Device != device || b.Grant.Exp == "" {
			fail(fmt.Errorf("mint wire"))
			return
		}
		if len(f.mintStatuses) > 0 {
			status := f.mintStatuses[0]
			f.mintStatuses = f.mintStatuses[1:]
			if status != 200 {
				w.Header().Set("Retry-After", f.retryAfter)
				w.WriteHeader(status)
				return
			}
		}
		now := time.Now().Add(f.dateOffset).UTC().Truncate(time.Second)
		claims := map[string]any{"exp": now.Add(10 * time.Minute).Unix(), "iat": now.Unix(), "nbf": now.Unix(), "iss": "https://auth.example", "sub": f.scope.User, "aud": []string{"telara-mcp-session"}, "tenant_id": f.scope.Tenant, "mcp_config_id": f.scope.Config, "cnf": map[string]any{"jkt": jkt}, "memory_grant": f.grant}
		if f.claims != nil {
			f.claims(claims)
		}
		tok, err := signJWT(f.authKey, map[string]any{"alg": "ES256", "typ": "JWT", "kid": "pinned"}, claims)
		if err != nil {
			fail(err)
			return
		}
		f.tokens = append(f.tokens, tok)
		response := map[string]any{"session_token": tok, "expires_at": claims["exp"]}
		if f.mintResponse != nil {
			f.mintResponse(response)
		}
		w.Header().Set("Date", now.Format(http.TimeFormat))
		_ = json.NewEncoder(w).Encode(response)
		return
	}
	if r.URL.Path != "/v1/memory/import" {
		fail(fmt.Errorf("path"))
		return
	}
	f.pushCount++
	f.proofs = append(f.proofs, r.Header.Get("DPoP"))
	data, _ := io.ReadAll(io.LimitReader(r.Body, MaxRequestBytes+1))
	f.requests = append(f.requests, append([]byte(nil), data...))
	status := 200
	if len(f.statuses) > 0 {
		status = f.statuses[0]
		f.statuses = f.statuses[1:]
	}
	if status != 200 && status != -1 {
		if f.redirect != "" {
			w.Header().Set("Location", f.redirect)
		}
		w.Header().Set("Retry-After", f.retryAfter)
		w.WriteHeader(status)
		return
	}
	// The fixture implements the import envelope and per-ID stored receipt wire
	// contract. It verifies actual record signatures, metadata allowlists and
	// decoded limits. It is unit evidence, not a mock-stack integration claim.
	req, records, err := fixtureDecodeRequest(data)
	if err != nil {
		f.handlerErr = err
		w.WriteHeader(400)
		return
	}

	var results []Result
	for i, r := range records {
		message, _ := sig.RecordMessage(r.ID)
		if sig.Verify(f.recordKey.Public().(ed25519.PublicKey), sig.CtxRecord, message, req.Envelopes[i].Sigs[0]) != nil {
			w.WriteHeader(400)
			return
		}
		receipt, exists := f.saved[r.ID]
		if !exists {
			receipt, _ = sig.SignReceipt(f.receiptKey, record.Receipt{ID: r.ID, Tenant: f.scope.Tenant, DeviceID: device, AcceptedAt: time.Now().UnixMilli(), HSeq: int64(len(f.saved) + 1), Policy: strings.Repeat("c", 64)})
			f.saved[r.ID] = receipt
		}
		resultStatus := "accepted"
		if exists {
			resultStatus = "accepted-duplicate"
		}
		copyReceipt := receipt
		results = append(results, Result{ID: r.ID, Status: resultStatus, HSeq: receipt.HSeq, Receipt: &copyReceipt, HostedTaskID: "hosted-task"})
	}
	if status == -1 {
		conn, _, _ := w.(http.Hijacker).Hijack()
		_ = conn.Close()
		return
	}
	if f.response != nil {
		results = f.response(results)
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
}

// fixtureProof ports the Gateway memoryDPoP/VerifyDPoPProof ES256 path without
// importing the gateway or calling the client's proof verifier. Its replay set
// models the mandatory one-use ledger shared by the gateway and import ingress.
func fixtureProof(token, method, target, credential string, now time.Time, seen map[string]bool) (string, error) {
	bad := func() (string, error) { return "", fmt.Errorf("invalid proof") }
	if len(token) > 16384 || credential == "" {
		return bad()
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return bad()
	}
	decode := func(s string) ([]byte, error) {
		v, err := base64.RawURLEncoding.Strict().DecodeString(s)
		if err != nil || base64.RawURLEncoding.EncodeToString(v) != s {
			return nil, fmt.Errorf("encoding")
		}
		return v, nil
	}
	headRaw, err := decode(parts[0])
	if err != nil {
		return bad()
	}
	var header map[string]json.RawMessage
	if json.Unmarshal(headRaw, &header) != nil {
		return bad()
	}
	var alg, typ string
	_ = json.Unmarshal(header["alg"], &alg)
	_ = json.Unmarshal(header["typ"], &typ)
	if alg != "ES256" || !strings.EqualFold(typ, "dpop+jwt") {
		return bad()
	}
	var key map[string]string
	if json.Unmarshal(header["jwk"], &key) != nil || key["kty"] != "EC" || key["crv"] != "P-256" {
		return bad()
	}
	for _, name := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
		if _, ok := key[name]; ok {
			return bad()
		}
	}
	xb, e := decode(key["x"])
	yb, e2 := decode(key["y"])
	if e != nil || e2 != nil || len(xb) != 32 || len(yb) != 32 {
		return bad()
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(xb), Y: new(big.Int).SetBytes(yb)}
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return bad()
	}
	signature, e := decode(parts[2])
	if e != nil || len(signature) != 64 {
		return bad()
	}
	hash := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(pub, hash[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
		return bad()
	}
	raw, e := decode(parts[1])
	if e != nil {
		return bad()
	}
	var claims struct {
		HTM, HTU, ATH, JTI string
		IAT                int64
	}
	if json.Unmarshal(raw, &claims) != nil {
		return bad()
	}
	canonical := func(s string) string {
		u, err := url.Parse(s)
		if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil {
			return ""
		}
		u.Scheme = strings.ToLower(u.Scheme)
		u.Host = strings.ToLower(u.Host)
		u.RawQuery = ""
		u.Fragment = ""
		if u.Path == "" {
			u.Path = "/"
		}
		return u.String()
	}
	want := sha256.Sum256([]byte(credential))
	if claims.JTI == "" || len(claims.JTI) > 256 || !strings.EqualFold(claims.HTM, method) || canonical(claims.HTU) == "" || canonical(claims.HTU) != canonical(target) || claims.ATH != base64.RawURLEncoding.EncodeToString(want[:]) || time.Unix(claims.IAT, 0).After(now.Add(30*time.Second)) || now.Sub(time.Unix(claims.IAT, 0)) > 60*time.Second {
		return bad()
	}
	canonicalJWK := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":%q,"y":%q}`, key["x"], key["y"])
	digest := sha256.Sum256([]byte(canonicalJWK))
	jkt := base64.RawURLEncoding.EncodeToString(digest[:])
	id := jkt + "\x00" + claims.JTI
	if seen[id] {
		return bad()
	}
	seen[id] = true
	return jkt, nil
}

// This is a bounded port of the import Decode/ParseRequest path for the raw
// Zstandard blocks this client emits. It deliberately does not call the client
// operation restorer or frame reader. General compressed-frame interoperability
// is additionally checked through the independent frozen decoder vectors.
func fixtureDecodeRequest(raw []byte) (request, []*record.Record, error) {
	var req request
	if len(raw) > 4<<20 || strictJSON(raw, &req) != nil || !validOpID(req.OpID) || len(req.Envelopes) < 1 || len(req.Envelopes) > 64 {
		return req, nil, ErrInvalid
	}
	var records []*record.Record
	total := 0
	seen := map[string]bool{}
	for _, e := range req.Envelopes {
		if e.V != 3 || e.Receipt != nil || e.Grant != nil || e.Body == nil || e.Body.Codec != "zstd" || len(e.Sigs) < 1 || len(e.Sigs) > 2 {
			return req, nil, ErrInvalid
		}
		h, err := base64.RawURLEncoding.Strict().DecodeString(e.Header)
		if err != nil || len(h) > 16384 {
			return req, nil, ErrInvalid
		}
		compressed, err := base64.RawURLEncoding.Strict().DecodeString(e.Body.Bytes)
		if err != nil || len(compressed) > record.MaxBodyBytes+65536 {
			return req, nil, ErrInvalid
		}
		reader := bytes.NewReader(compressed)
		var magic [5]byte
		if _, err = io.ReadFull(reader, magic[:]); err != nil || magic != [5]byte{0x28, 0xb5, 0x2f, 0xfd, 0xa0} {
			return req, nil, ErrInvalid
		}
		var size uint32
		if binary.Read(reader, binary.LittleEndian, &size) != nil || size == 0 || size > record.MaxBodyBytes {
			return req, nil, ErrInvalid
		}
		var body bytes.Buffer
		for {
			var block [3]byte
			if _, err = io.ReadFull(reader, block[:]); err != nil {
				return req, nil, ErrInvalid
			}
			header := uint32(block[0]) | uint32(block[1])<<8 | uint32(block[2])<<16
			length := int64(header >> 3)
			if header&6 != 0 || length < 1 || length > 128<<10 || length > int64(size)-int64(body.Len()) {
				return req, nil, ErrInvalid
			}
			if _, err = io.CopyN(&body, reader, length); err != nil {
				return req, nil, ErrInvalid
			}
			if header&1 != 0 {
				break
			}
		}
		if body.Len() != int(size) || reader.Len() != 0 {
			return req, nil, ErrInvalid
		}
		r, err := record.Parse(h, body.Bytes(), e.ID)
		if err != nil || seen[e.ID] {
			return req, nil, ErrInvalid
		}
		seen[e.ID] = true
		if r.Header.Type != record.KindTask && r.Header.Type != record.KindSession && r.Header.Type != record.KindErasure && r.Header.Type != record.KindRetraction && r.Header.Type != record.KindKeyOp {
			return req, nil, ErrInvalid
		}
		if !r.Header.Type.IsControl() && (r.Header.Red.Profile != record.ProfilePushMetadata || r.Header.Prov != record.ProvDerived) {
			return req, nil, ErrInvalid
		}
		total += len(h) + body.Len()
		if total > 4<<20 {
			return req, nil, ErrInvalid
		}
		records = append(records, r)
	}
	return req, records, nil
}
