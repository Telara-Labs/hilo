package disclosure

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/custodyguard"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	"github.com/Telara-Labs/telara-memory/contract/record"
)

// RepositoryContext is owner-produced public credential metadata. The actual
// credential secret remains in the native vault; no selector grants authority.
// Pending and retired slots remain inventoried until native deletion is known.
type RepositoryContext struct {
	ID         string `json:"id"`
	Binding    string `json:"binding"`
	Generation int64  `json:"generation"`
	Credential string `json:"credential,omitempty"`
	Handle     string `json:"vault_handle,omitempty"`
	State      string `json:"state"`
	Native     string `json:"native"`
}

type repositoryContextFile struct {
	Version  int                 `json:"version"`
	Owner    string              `json:"owner"`
	Machine  string              `json:"machine"`
	Contexts []RepositoryContext `json:"contexts"`
}

func contextOpaqueID(value string) bool {
	b, err := hex.DecodeString(value)
	return err == nil && len(b) == 16 && hex.EncodeToString(b) == value
}

func loadRepositoryContexts(dir string) (repositoryContextFile, error) {
	var out repositoryContextFile
	owner, machine, err := store.InstalledIdentity(dir)
	if err != nil {
		return out, installedFailure()
	}
	data, err := store.ReadProfileRecord(dir, store.RepositoryContextsName)
	if err != nil {
		if _, statErr := os.Lstat(filepath.Join(dir, store.RepositoryContextsName)); errors.Is(statErr, os.ErrNotExist) {
			return repositoryContextFile{Version: 1, Owner: owner, Machine: machine}, nil
		}
		return out, installedFailure()
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&out) != nil || d.Decode(new(any)) != io.EOF || out.Version != 1 || out.Owner != owner || out.Machine != machine || len(out.Contexts) > 32 {
		return repositoryContextFile{}, installedFailure()
	}
	ids, credentials, handles := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, c := range out.Contexts {
		if !contextOpaqueID(c.ID) || ids[c.ID] || !record.IsHex64(c.Binding) || c.Generation <= 0 {
			return repositoryContextFile{}, installedFailure()
		}
		ids[c.ID] = true
		if c.Native != "unstarted" && c.Native != "creating" && c.Native != "created" {
			return repositoryContextFile{}, installedFailure()
		}
		if c.State == "active" && c.Native != "created" {
			return repositoryContextFile{}, installedFailure()
		}
		switch c.State {
		case "pending":
			if c.Credential != "" && !record.IsUUIDv4(c.Credential) {
				return repositoryContextFile{}, installedFailure()
			}
		case "active":
			if !record.IsUUIDv4(c.Credential) {
				return repositoryContextFile{}, installedFailure()
			}
		case "retiring", "retired", "removed":
			if c.Credential != "" && !record.IsUUIDv4(c.Credential) {
				return repositoryContextFile{}, installedFailure()
			}
		default:
			return repositoryContextFile{}, installedFailure()
		}
		if c.State == "removed" {
			if c.Handle != "" {
				return repositoryContextFile{}, installedFailure()
			}
		} else if !contextOpaqueID(c.Handle) || handles[c.Handle] {
			return repositoryContextFile{}, installedFailure()
		}
		if c.Credential != "" {
			if credentials[c.Credential] {
				return repositoryContextFile{}, installedFailure()
			}
			credentials[c.Credential] = true
		}
		handles[c.Handle] = true
	}
	return out, nil
}

// OwnedCredentialHandles participates in the complete typed installation
// inventory. Its caller retains custodyguard admission across the snapshot.
func OwnedCredentialHandles(dir string) ([]custodyguard.Handle, error) {
	f, err := loadRepositoryContexts(dir)
	if err != nil {
		return nil, err
	}
	var out []custodyguard.Handle
	for _, c := range f.Contexts {
		if c.State == "removed" || c.Native == "unstarted" {
			continue
		}
		purpose := "repository-context"
		if c.State == "retiring" || c.State == "retired" {
			purpose = "repository-context-retired"
		}
		out = append(out, custodyguard.Handle{Handle: c.Handle, Purpose: purpose})
	}
	return out, nil
}

func writeRepositoryContexts(dir string, f repositoryContextFile) error {
	data, err := json.Marshal(f)
	if err != nil {
		return installedFailure()
	}
	return store.WriteProfileRecord(dir, store.RepositoryContextsName, data)
}

// EnrollRepositoryContext is owner administration. It stores a planned native
// slot before creation and never publishes the secret to argv or JSON.
func EnrollRepositoryContext(ctx context.Context, dir string, st *store.Store, admin *Administration, vault SecretVault, q store.RepositoryEnrollment) (RepositoryContext, error) {
	var out RepositoryContext
	if st == nil || admin == nil || vault == nil {
		return out, installedFailure()
	}
	err := custodyguard.With(ctx, dir, func(ctx context.Context) error {
		f, err := loadRepositoryContexts(dir)
		if err != nil {
			return err
		}
		if len(f.Contexts) >= 32 {
			return installedFailure()
		}
		b, err := st.EnrollRepository(ctx, q)
		if err != nil {
			return err
		}
		id, err := opaqueID()
		if err != nil {
			return err
		}
		handle, err := opaqueID()
		if err != nil {
			return err
		}
		c := RepositoryContext{ID: id, Binding: b.ID, Generation: b.Generation, Handle: handle, State: "pending", Native: "unstarted"}
		f.Contexts = append(f.Contexts, c)
		slot := len(f.Contexts) - 1
		if err = writeRepositoryContexts(dir, f); err != nil {
			return err
		}
		repos, err := store.ConcreteRepos([]string{b.Repo})
		if err != nil {
			return err
		}
		client, err := admin.RegisterRepository(ctx, RegisterClient{AdminOpID: "repository-" + id, ClientName: "Owner repository context", ReadGrant: Grant{Repos: repos, Channels: []Channel{S}}, TaskWrites: TaskWriteGrant{Repos: repos, Actions: []TaskMutation{Create, Checkpoint, Pause, Complete}}}, b.ID, b.Generation)
		if err != nil {
			return err
		}
		token, err := client.Secret.Take()
		if err != nil {
			return err
		}
		defer clear(token)
		c.Credential = client.CredentialID
		f.Contexts[slot] = c
		if err = writeRepositoryContexts(dir, f); err != nil {
			return err
		}
		c.Native = "creating"
		f.Contexts[slot] = c
		if err = writeRepositoryContexts(dir, f); err != nil {
			return err
		}
		if err = vault.Put(ctx, c.Handle, token); err != nil {
			return err
		}
		c.State = "active"
		c.Native = "created"
		f.Contexts[slot] = c
		if err = writeRepositoryContexts(dir, f); err != nil {
			return err
		}
		out = c
		return nil
	})
	return out, err
}

// RetireRepositoryContext keeps all native slots inventoried while signed
// retirement is pending. It is repeatable after a failed deletion or restart.
func RetireRepositoryContext(ctx context.Context, dir, id string, st *store.Store, vault SecretVault, signer store.ControlSigner) ([]string, error) {
	var controls []string
	if st == nil || vault == nil || !record.IsHex64(id) {
		return nil, installedFailure()
	}
	err := custodyguard.With(ctx, dir, func(ctx context.Context) error {
		f, err := loadRepositoryContexts(dir)
		if err != nil {
			return err
		}
		for i := range f.Contexts {
			if f.Contexts[i].Binding == id && f.Contexts[i].State != "removed" {
				f.Contexts[i].State = "retiring"
			}
		}
		if err = writeRepositoryContexts(dir, f); err != nil {
			return err
		}
		controls, err = st.RevokeRepository(ctx, id, signer)
		if err != nil {
			return err
		}
		for i := range f.Contexts {
			c := &f.Contexts[i]
			if c.Binding != id || c.State == "removed" {
				continue
			}
			c.State = "retired"
			if err = writeRepositoryContexts(dir, f); err != nil {
				return err
			}
			switch c.Native {
			case "unstarted": // The durable phase precedes every possible native call.
			case "creating":
				cleanup, ok := vault.(interface {
					AbandonPlanned(context.Context, string) error
				})
				if !ok {
					return installedFailure()
				}
				if err = cleanup.AbandonPlanned(ctx, c.Handle); err != nil {
					return err
				}
			case "created":
				if err = vault.Delete(ctx, c.Handle); err != nil {
					return err
				}
			default:
				return installedFailure()
			}
			c.Handle = ""
			c.State = "removed"
			if err = writeRepositoryContexts(dir, f); err != nil {
				return err
			}
		}
		return nil
	})
	return controls, err
}
func repositoryContextProof(ctx context.Context, dir, id string, vault SecretVault) (CredentialProof, error) {
	if !contextOpaqueID(id) {
		return CredentialProof{}, installedFailure()
	}
	f, err := loadRepositoryContexts(dir)
	if err != nil {
		return CredentialProof{}, err
	}
	for _, c := range f.Contexts {
		if c.ID == id {
			if c.State != "active" {
				return CredentialProof{}, installedFailure()
			}
			secret, err := vault.Get(ctx, c.Handle)
			defer clear(secret)
			if err != nil || len(secret) != 32 {
				return CredentialProof{}, installedFailure()
			}
			return CredentialProof{CredentialID: c.Credential, Token: append([]byte(nil), secret...)}, nil
		}
	}
	return CredentialProof{}, installedFailure()
}
