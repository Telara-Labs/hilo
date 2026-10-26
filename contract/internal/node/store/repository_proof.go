package store

import (
	"context"
	"strings"

	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
)

// verifiedRepositoryRemote resolves only signed current same-owner session
// evidence. A repository hash is an identity, never a permission. Callers must
// separately apply current tenant policy and explicit sync grants/rules.
func (d *databaseState) verifiedRepositoryRemote(repo string) string {
	if !strings.HasPrefix(repo, "r1:") || !record.IsHex64(strings.TrimPrefix(repo, "r1:")) {
		return ""
	}
	remote := ""
	for _, x := range d.records {
		h := x.rec.Header
		if x.owner != d.store.opts.PinnedGenesisID || x.state != "live" || x.sigStatus != sig.StatusVerified || h.Subj.RepoID != repo {
			continue
		}
		if d.tenant != nil && (h.Pol == "" || d.policyTenants[h.Pol] != d.tenant.tenant || d.policyLogout[h.Pol]) {
			continue
		}
		var id, value string
		switch b := x.rec.Body.(type) {
		case *record.SessionBody:
			if b.Repo != nil {
				id, value = b.Repo.ID, b.Repo.Remote
			}
		case *record.SessionMetaBody:
			if b.Repo != nil {
				id, value = b.Repo.ID, b.Repo.Remote
			}
		default:
			continue
		}
		computed, err := record.RepoID(value)
		// Conflicting claimed evidence refuses the identity as a whole. It cannot
		// be used to pick whichever mapping happens to allow a policy glob.
		if err != nil || id != repo || computed != repo {
			return ""
		}
		if remote != "" && remote != value {
			return ""
		}
		remote = value
	}
	return remote
}

// RepositoryRemote exposes the same resolver to the sync exporter. It reads
// current signature, invalidation and tenant-lineage state under the writer.
func (s *Store) RepositoryRemote(ctx context.Context, repo string) (string, error) {
	var remote string
	err := s.write(ctx, func() error {
		d, err := s.load(ctx)
		if err != nil {
			return err
		}
		if d.blocked {
			return d.blockedError()
		}
		remote = d.verifiedRepositoryRemote(repo)
		return nil
	})
	return remote, err
}
