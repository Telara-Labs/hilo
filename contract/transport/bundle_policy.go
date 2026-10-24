package transport

import (
	"github.com/Telara-Labs/telara-memory/contract/policy"
	"github.com/Telara-Labs/telara-memory/contract/record"
)

// BundleAuthorization is verified CURRENT receiver authority for either export
// or import. Preview, shape and policy checks occur under the disclosure fence.
type BundleAuthorization struct {
	ProvenanceKnown                                         bool
	LogoutRestricted                                        bool // authenticated retained per-record logout fence, including after relogin
	ActivePolicy                                            bool
	Policy                                                  *record.PolicyBody
	Freshness                                               policy.Freshness
	LoggedIn, Applicable, ShapesSatisfied, PreviewConfirmed bool
	Repo                                                    string
}

func BundlePolicyAllowed(r *record.Record, a BundleAuthorization) bool {
	if r == nil || !a.ProvenanceKnown || a.LogoutRestricted {
		return false
	}
	parsed, err := record.Parse(r.HeaderJCS, r.BodyJCS, r.ID)
	if err != nil || parsed.Body == nil {
		return false
	}
	r = parsed
	if record.ReservedProfiles[r.Header.Red.Profile] {
		return false
	}
	governed := a.ActivePolicy || r.Header.Pol != ""
	if !governed {
		return r.Header.Red.Profile == record.ProfileLocal || r.Header.Red.Profile == record.ProfilePushMetadata
	}
	if r.Header.Red.Profile != record.ProfilePushMetadata || (r.Header.Type != record.KindTask && r.Header.Type != record.KindSession) || !a.LoggedIn || !a.Applicable || a.Policy == nil || (a.Freshness != policy.Fresh && a.Freshness != policy.RefreshDue) || a.Policy.Kill.Sync || !a.ShapesSatisfied || r.Header.Red.Epoch < a.Policy.Redaction.MinEpoch || a.Policy.Push.RequirePreview && !a.PreviewConfirmed {
		return false
	}
	return policy.PushAllowed(a.Policy, a.Repo)
}
