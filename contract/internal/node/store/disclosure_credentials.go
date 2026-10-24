package store

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"math"
	"sort"
	"strings"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/disclosuretext"
	"github.com/Telara-Labs/telara-memory/contract/jcs"
	"github.com/Telara-Labs/telara-memory/contract/record"
)

type credentialState struct {
	id, name, readKind, writeKind string
	epoch                         int64
	revoked, unscoped             bool
	verifier                      []byte
	repos, writeRepos             map[string]bool
	channels                      map[Channel]bool
	actions                       map[TaskMutation]bool
}

func repoKind(r RepoSet) (string, error) {
	switch r.kind {
	case "":
		if len(r.ids) == 0 {
			return "deny", nil
		}
	case "all-local":
		if len(r.ids) == 0 {
			return r.kind, nil
		}
	case "concrete":
		if _, e := ConcreteRepos(r.ids); e == nil {
			return r.kind, nil
		}
	}
	return "", failure("invalid_grant")
}
func validateGrants(g Grant, w TaskWriteGrant) error {
	if _, e := repoKind(g.Repos); e != nil {
		return e
	}
	k, e := repoKind(w.Repos)
	if e != nil {
		return e
	}
	if w.AllowUnscoped && k != "all-local" {
		return failure("invalid_grant")
	}
	seen := map[Channel]bool{}
	for _, c := range g.Channels {
		if seen[c] || (c != S && c != P && c != E) {
			return failure("invalid_grant")
		}
		seen[c] = true
	}
	as := map[TaskMutation]bool{}
	for _, a := range w.Actions {
		if as[a] || (a != Create && a != Checkpoint && a != Pause && a != Complete) {
			return failure("invalid_grant")
		}
		as[a] = true
	}
	return nil
}
func verifierFor(id string, token []byte) []byte {
	raw, _ := jcs.StringArray("local-client-verifier/1", id, base64.RawURLEncoding.EncodeToString(token))
	defer clear(raw)
	v := sha256.Sum256(raw)
	return append([]byte(nil), v[:]...)
}
func (s *Store) credential(ctx context.Context, id string) (*credentialState, error) {
	c := &credentialState{id: id, repos: map[string]bool{}, writeRepos: map[string]bool{}, channels: map[Channel]bool{}, actions: map[TaskMutation]bool{}}
	var revoked, unscoped int
	var owner, machine string
	err := s.conn.QueryRowContext(ctx, "SELECT owner,machine,name,verifier,epoch,revoked,read_repo_kind,write_repo_kind,allow_unscoped FROM client_credential WHERE id=?", id).Scan(&owner, &machine, &c.name, &c.verifier, &c.epoch, &revoked, &c.readKind, &c.writeKind, &unscoped)
	if err == sql.ErrNoRows {
		return nil, failure("unauthorized")
	}
	if err != nil {
		return nil, failure("storage_error")
	}
	if owner != s.opts.PinnedGenesisID || machine != s.opts.LocalMachineID || c.epoch <= 0 {
		return nil, failure("corrupt_database")
	}
	c.revoked = revoked != 0
	c.unscoped = unscoped != 0
	for _, spec := range []struct {
		query string
		kind  int
	}{{"SELECT repo FROM client_grant_repo WHERE credential=?", 0}, {"SELECT repo FROM client_task_write_repo WHERE credential=?", 1}, {"SELECT channel FROM client_grant_channel WHERE credential=?", 2}, {"SELECT action FROM client_task_write WHERE credential=?", 3}} {
		rows, e := s.conn.QueryContext(ctx, spec.query, id)
		if e != nil {
			return nil, failure("storage_error")
		}
		count := 0
		for rows.Next() {
			var value string
			if rows.Scan(&value) != nil {
				rows.Close()
				return nil, failure("storage_error")
			}
			count++
			limit := 64
			if spec.kind == 2 {
				limit = 3
			}
			if spec.kind == 3 {
				limit = 4
			}
			if count > limit {
				rows.Close()
				return nil, failure("corrupt_database")
			}
			if spec.kind < 2 && !record.IsRepoID(value) {
				rows.Close()
				return nil, failure("corrupt_database")
			}
			switch spec.kind {
			case 0:
				c.repos[value] = true
			case 1:
				c.writeRepos[value] = true
			case 2:
				c.channels[Channel(value)] = true
			case 3:
				c.actions[TaskMutation(value)] = true
			}
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return nil, failure("storage_error")
		}
	}
	return c, nil
}
func (e *DisclosureEngine) client(ctx context.Context, h ClientHandle) (*credentialState, error) {
	if h.engine != e || e.closed || h.connection == "" || e.clients[h.connection] == nil {
		return nil, failure("unauthorized")
	}
	if err := e.checkAuthority(ctx); err != nil {
		return nil, err
	}
	c, err := e.store.credential(ctx, h.credential)
	if err != nil {
		return nil, err
	}
	if c.revoked || c.epoch != h.epoch {
		return nil, failure("unauthorized")
	}
	return c, nil
}
func (e *DisclosureEngine) Authenticate(ctx context.Context, p CredentialProof) (ClientHandle, error) {
	if e == nil || e.store == nil || !record.IsUUIDv4(p.CredentialID) || len(p.Token) != 32 {
		return ClientHandle{}, failure("unauthorized")
	}
	token := append([]byte(nil), p.Token...)
	defer clear(token)
	pool, err := newDisclosureEntropy()
	if err != nil {
		return ClientHandle{}, err
	}
	defer pool.clear()
	var h ClientHandle
	err = e.store.writeMode(ctx, true, func() error {
		if err := e.checkAuthority(ctx); err != nil {
			return err
		}
		c, err := e.store.credential(ctx, p.CredentialID)
		if err != nil {
			return err
		}
		v := verifierFor(p.CredentialID, token)
		defer clear(v)
		if c.revoked || len(c.verifier) != 32 || subtle.ConstantTimeCompare(c.verifier, v) != 1 {
			return failure("unauthorized")
		}
		id, err := pool.uuid(ctx, e.store, "connection", "", "")
		if err != nil {
			return err
		}
		if len(e.clients) >= 4096 {
			return failure("connection_limit")
		}
		id = strings.ReplaceAll(id, "-", "")
		h = ClientHandle{e, c.id, id, c.epoch}
		e.clients[id] = &liveClient{rpc: map[string]string{}}
		return nil
	})
	if err != nil {
		e.store.mu.Lock()
		delete(e.clients, h.connection)
		e.store.mu.Unlock()
		return ClientHandle{}, err
	}
	return h, nil
}
func sortedCopy[T ~string](in []T) []string {
	v := make([]string, len(in))
	for i, s := range in {
		v[i] = string(s)
	}
	sort.Strings(v)
	return v
}
func adminHash(command, credential string, epoch int64, g Grant, w TaskWriteGrant) (string, error) {
	rk, _ := repoKind(g.Repos)
	wk, _ := repoKind(w.Repos)
	raw, err := jcs.Marshal(map[string]any{"command": command, "credential": credential, "epoch": epoch, "read_kind": rk, "read_repos": sortedCopy(g.Repos.ids), "channels": sortedCopy(g.Channels), "write_kind": wk, "write_repos": sortedCopy(w.Repos.ids), "actions": sortedCopy(w.Actions), "unscoped": w.AllowUnscoped})
	if err != nil {
		return "", failure("invalid_grant")
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
func (a *DisclosureAdministration) valid() bool {
	return a != nil && a.engine != nil && a.engine.store != nil
}
func (a *DisclosureAdministration) prior(ctx context.Context, op, command, hash string) (GrantReceipt, bool, error) {
	var r GrantReceipt
	var oldCommand, oldHash string
	e := a.engine
	s := e.store
	err := s.conn.QueryRowContext(ctx, "SELECT command,args_hash,credential,epoch FROM admin_outcome WHERE owner=? AND machine=? AND key_id=? AND op=?", s.opts.PinnedGenesisID, s.opts.LocalMachineID, e.authority.keyID, op).Scan(&oldCommand, &oldHash, &r.CredentialID, &r.GrantEpoch)
	if err == sql.ErrNoRows {
		return r, false, nil
	}
	if err != nil {
		return r, false, failure("storage_error")
	}
	if oldCommand != command || oldHash != hash {
		return r, true, failure("op_conflict")
	}
	r.Status = "already_recorded"
	return r, true, nil
}
func (a *DisclosureAdministration) save(ctx context.Context, op, command, hash string, r GrantReceipt) error {
	e := a.engine
	_, err := e.store.conn.ExecContext(ctx, "INSERT INTO admin_outcome VALUES(?,?,?,?,?,?,?,?)", e.config.OwnerGenesis, e.config.MachineID, e.authority.keyID, op, command, hash, r.CredentialID, r.GrantEpoch)
	if err != nil {
		return failure("storage_error")
	}
	return nil
}
func (s *Store) bump(ctx context.Context) error {
	var g int64
	if s.conn.QueryRowContext(ctx, "SELECT generation FROM meta WHERE singleton=1").Scan(&g) != nil {
		return failure("storage_error")
	}
	if g == math.MaxInt64 {
		return failure("ordinal_limit")
	}
	if _, err := s.conn.ExecContext(ctx, "UPDATE meta SET generation=? WHERE singleton=1", g+1); err != nil {
		return failure("storage_error")
	}
	if _, err := s.conn.ExecContext(ctx, "DELETE FROM render_body"); err != nil {
		return failure("storage_error")
	}
	return nil
}
func (s *Store) putGrants(ctx context.Context, id string, g Grant, w TaskWriteGrant) error {
	if err := validateGrants(g, w); err != nil {
		return err
	}
	rk, _ := repoKind(g.Repos)
	wk, _ := repoKind(w.Repos)
	if _, err := s.conn.ExecContext(ctx, "UPDATE client_credential SET read_repo_kind=?,write_repo_kind=?,allow_unscoped=? WHERE id=?", rk, wk, boolInt(w.AllowUnscoped), id); err != nil {
		return failure("storage_error")
	}
	for _, t := range []string{"client_grant_repo", "client_grant_channel", "client_task_write", "client_task_write_repo"} {
		if _, err := s.conn.ExecContext(ctx, "DELETE FROM "+t+" WHERE credential=?", id); err != nil {
			return failure("storage_error")
		}
	}
	for _, spec := range []struct {
		q      string
		values []string
	}{{"INSERT INTO client_grant_repo VALUES(?,?)", sortedCopy(g.Repos.ids)}, {"INSERT INTO client_grant_channel VALUES(?,?)", sortedCopy(g.Channels)}, {"INSERT INTO client_task_write VALUES(?,?)", sortedCopy(w.Actions)}, {"INSERT INTO client_task_write_repo VALUES(?,?)", sortedCopy(w.Repos.ids)}} {
		for _, v := range spec.values {
			if _, err := s.conn.ExecContext(ctx, spec.q, id, v); err != nil {
				return failure("storage_error")
			}
		}
	}
	return nil
}
func grantsFrom(c *credentialState) (Grant, TaskWriteGrant) {
	g := Grant{Repos: RepoSet{kind: c.readKind}}
	w := TaskWriteGrant{Repos: RepoSet{kind: c.writeKind}, AllowUnscoped: c.unscoped}
	if g.Repos.kind == "deny" {
		g.Repos.kind = ""
	}
	if w.Repos.kind == "deny" {
		w.Repos.kind = ""
	}
	for id := range c.repos {
		g.Repos.ids = append(g.Repos.ids, id)
	}
	for id := range c.writeRepos {
		w.Repos.ids = append(w.Repos.ids, id)
	}
	for ch := range c.channels {
		g.Channels = append(g.Channels, ch)
	}
	for a := range c.actions {
		w.Actions = append(w.Actions, a)
	}
	return g, w
}
func (a *DisclosureAdministration) Register(ctx context.Context, q RegisterClient) (RegisteredClient, error) {
	var out RegisteredClient
	if !a.valid() {
		return out, failure("unauthorized")
	}
	if disclosuretext.ValidateIdentity(disclosuretext.AdminOpID, q.AdminOpID) != nil || disclosuretext.ValidateIdentity(disclosuretext.ClientName, q.ClientName) != nil {
		return out, failure("unsafe_identity")
	}
	if err := validateGrants(q.ReadGrant, q.TaskWrites); err != nil {
		return out, err
	}
	hash, err := adminHash("register", q.ClientName, 0, q.ReadGrant, q.TaskWrites)
	if err != nil {
		return out, err
	}
	pool, err := newDisclosureEntropy()
	if err != nil {
		return out, err
	}
	defer pool.clear()
	replay := false
	err = a.engine.store.writeMode(ctx, true, func() error {
		e := a.engine
		s := e.store
		if err := e.checkAuthority(ctx); err != nil {
			return err
		}
		prior, exists, err := a.prior(ctx, q.AdminOpID, "register", hash)
		if err != nil {
			return err
		}
		if exists {
			out.CredentialID = prior.CredentialID
			out.GrantEpoch = prior.GrantEpoch
			replay = true
			return nil
		}
		var n int
		if s.conn.QueryRowContext(ctx, "SELECT count(*) FROM client_credential WHERE revoked=0").Scan(&n) != nil {
			return failure("storage_error")
		}
		if n >= 64 {
			return failure("credential_limit")
		}
		id, err := pool.uuid(ctx, s, "credential", "client_credential", "id")
		if err != nil {
			return err
		}
		v := verifierFor(id, pool.secret)
		defer clear(v)
		if _, err = s.conn.ExecContext(ctx, "INSERT INTO client_credential VALUES(?,?,?,?,?,1,0,'deny','deny',0)", id, e.config.OwnerGenesis, e.config.MachineID, q.ClientName, v); err != nil {
			return failure("storage_error")
		}
		if err = s.putGrants(ctx, id, q.ReadGrant, q.TaskWrites); err != nil {
			return err
		}
		if err = a.save(ctx, q.AdminOpID, "register", hash, GrantReceipt{CredentialID: id, GrantEpoch: 1}); err != nil {
			return err
		}
		if err = s.bump(ctx); err != nil {
			return err
		}
		out = RegisteredClient{CredentialID: id, GrantEpoch: 1}
		return nil
	})
	if err != nil {
		return RegisteredClient{}, err
	}
	if replay {
		return out, failure("secret_unavailable_rotate_required")
	}
	out.Secret = &OneUseSecret{value: append([]byte(nil), pool.secret...)}
	return out, nil
}
func (a *DisclosureAdministration) change(ctx context.Context, op, id string, expected int64, command string, g Grant, w TaskWriteGrant) (GrantReceipt, []byte, error) {
	var out GrantReceipt
	if !a.valid() {
		return out, nil, failure("unauthorized")
	}
	if disclosuretext.ValidateIdentity(disclosuretext.AdminOpID, op) != nil {
		return out, nil, failure("unsafe_identity")
	}
	if !record.IsUUIDv4(id) || expected <= 0 {
		return out, nil, failure("invalid_request")
	}
	if err := validateGrants(g, w); err != nil {
		return out, nil, err
	}
	hash, err := adminHash(command, id, expected, g, w)
	if err != nil {
		return out, nil, err
	}
	pool, err := newDisclosureEntropy()
	if err != nil {
		return out, nil, err
	}
	defer pool.clear()
	replay := false
	err = a.engine.store.writeMode(ctx, true, func() error {
		e := a.engine
		s := e.store
		if err := e.checkAuthority(ctx); err != nil {
			return err
		}
		r, exists, err := a.prior(ctx, op, command, hash)
		if err != nil {
			return err
		}
		if exists {
			out = r
			replay = true
			return nil
		}
		c, err := s.credential(ctx, id)
		if err != nil {
			return err
		}
		if c.revoked {
			return failure("unauthorized")
		}
		if c.epoch != expected {
			return failure("stale_grant")
		}
		if c.epoch == math.MaxInt64 {
			return failure("ordinal_limit")
		}
		oldG, oldW := grantsFrom(c)
		switch command {
		case "read_grant":
			oldG = g
		case "task_writes":
			oldW = w
		case "rotate", "revoke":
		default:
			return failure("invalid_request")
		}
		if err = s.putGrants(ctx, id, oldG, oldW); err != nil {
			return err
		}
		var v any = c.verifier
		revoked := 0
		if command == "rotate" {
			v = verifierFor(id, pool.secret)
		}
		if command == "revoke" {
			v = nil
			revoked = 1
		}
		if _, err = s.conn.ExecContext(ctx, "UPDATE client_credential SET epoch=?,verifier=?,revoked=? WHERE id=?", expected+1, v, revoked, id); err != nil {
			return failure("storage_error")
		}
		if _, err = s.conn.ExecContext(ctx, "UPDATE query_cursor SET state='expired' WHERE selection IN(SELECT id FROM query_selection WHERE credential=?)", id); err != nil {
			return failure("storage_error")
		}
		out = GrantReceipt{id, expected + 1, "changed"}
		if err = a.save(ctx, op, command, hash, out); err != nil {
			return err
		}
		return s.bump(ctx)
	})
	if err != nil {
		return GrantReceipt{}, nil, err
	}
	if command == "rotate" && replay {
		return out, nil, failure("secret_unavailable_rotate_required")
	}
	if command == "rotate" {
		return out, append([]byte(nil), pool.secret...), nil
	}
	return out, nil, nil
}
func (a *DisclosureAdministration) ReplaceGrant(ctx context.Context, op, id string, epoch int64, g Grant) (GrantReceipt, error) {
	r, _, e := a.change(ctx, op, id, epoch, "read_grant", g, TaskWriteGrant{})
	return r, e
}
func (a *DisclosureAdministration) ReplaceTaskWrites(ctx context.Context, op, id string, epoch int64, w TaskWriteGrant) (GrantReceipt, error) {
	r, _, e := a.change(ctx, op, id, epoch, "task_writes", Grant{}, w)
	return r, e
}
func (a *DisclosureAdministration) RevokeCredential(ctx context.Context, op, id string, epoch int64) (GrantReceipt, error) {
	r, _, e := a.change(ctx, op, id, epoch, "revoke", Grant{}, TaskWriteGrant{})
	return r, e
}
func (a *DisclosureAdministration) RotateCredential(ctx context.Context, op, id string, epoch int64) (RegisteredClient, error) {
	r, v, e := a.change(ctx, op, id, epoch, "rotate", Grant{}, TaskWriteGrant{})
	out := RegisteredClient{CredentialID: r.CredentialID, GrantEpoch: r.GrantEpoch}
	if e == nil {
		out.Secret = &OneUseSecret{value: v}
	}
	return out, e
}

type scopeState struct {
	id, repoState, repo  string
	generation, evidence int64
}

func (e *DisclosureEngine) scope(ctx context.Context, h ClientHandle, sh ScopeHandle) (scopeState, error) {
	var s scopeState
	if sh.engine != e || sh.credential != h.credential {
		return s, failure("invalid_scope")
	}
	err := e.store.conn.QueryRowContext(ctx, "SELECT id,generation,evidence,repo_state,repo FROM local_scope WHERE id=? AND credential=?", sh.id, h.credential).Scan(&s.id, &s.generation, &s.evidence, &s.repoState, &s.repo)
	if err == sql.ErrNoRows {
		return s, failure("invalid_scope")
	}
	if err != nil {
		return s, failure("storage_error")
	}
	return s, nil
}
func (e *DisclosureEngine) Resolve(ctx context.Context, h ClientHandle, input IdentityInput) (ScopeHandle, error) {
	var out ScopeHandle
	if e == nil || e.store == nil {
		return out, failure("unauthorized")
	}
	for _, v := range []struct {
		k disclosuretext.IdentityKind
		v string
	}{{disclosuretext.ConversationHandle, input.ConversationHandle}, {disclosuretext.LegacySessionID, input.LegacySessionID}, {disclosuretext.ShimHandle, input.ShimInstanceID}, {disclosuretext.NativeAnnouncementID, input.NativeAnnouncementID}} {
		if v.v != "" && disclosuretext.ValidateIdentity(v.k, v.v) != nil {
			return out, failure("unsafe_identity")
		}
	}
	if input.NativeAnnouncementID != "" || input.ShimInstanceID != "" || input.LegacySessionID != "" {
		return out, failure("scope_resolution_unsupported")
	}
	pool, err := newDisclosureEntropy()
	if err != nil {
		return out, err
	}
	defer pool.clear()
	err = e.store.writeMode(ctx, true, func() error {
		if _, err := e.client(ctx, h); err != nil {
			return err
		}
		kind, key := "conversation", input.ConversationHandle
		if key == "" {
			kind = "connection"
			key = h.connection
			e.clients[h.connection].ephemeral = true
		}
		var id string
		var g, ev int64
		err := e.store.conn.QueryRowContext(ctx, "SELECT id,generation,evidence FROM local_scope WHERE credential=? AND identity_kind=? AND handle_key=?", h.credential, kind, key).Scan(&id, &g, &ev)
		if err == nil {
			out = ScopeHandle{e, h.credential, id, g, ev}
			return nil
		}
		if err != sql.ErrNoRows {
			return failure("storage_error")
		}
		var count int
		if e.store.conn.QueryRowContext(ctx, "SELECT count(*) FROM local_scope WHERE credential=?", h.credential).Scan(&count) != nil {
			return failure("storage_error")
		}
		if count >= 4096 {
			return failure("scope_limit")
		}
		id, err = pool.uuid(ctx, e.store, "scope", "local_scope", "id")
		if err != nil {
			return err
		}
		id = "sc1:" + e.config.MachineID + ":" + strings.ReplaceAll(id, "-", "")
		if _, err = e.store.conn.ExecContext(ctx, "INSERT INTO local_scope VALUES(?,?,?,?,?,?,1,0,'unknown','','')", id, e.config.OwnerGenesis, e.config.MachineID, h.credential, kind, key); err != nil {
			return failure("storage_error")
		}
		if err = e.store.bump(ctx); err != nil {
			return err
		}
		out = ScopeHandle{e, h.credential, id, 1, 0}
		return nil
	})
	if err != nil {
		return ScopeHandle{}, err
	}
	return out, nil
}
