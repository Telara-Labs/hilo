package sig

import "github.com/Telara-Labs/hilo/contract/record"

// IssuerProvenance records the adapter's authenticated trust source. These facts
// are not decoded from records, envelopes, bundle metadata or asserted tenant IDs.
type IssuerProvenance string

const (
	PinnedTLSLogin         IssuerProvenance = "pinned-tls-login"
	AuthenticatedAdmission IssuerProvenance = "authenticated-admission"
)

// TrustedIssuer is receiver state supplied only after a validated TLS login pin
// or authenticated admission. Pure verifiers cannot authenticate network I/O.
type TrustedIssuer struct {
	Tenant     string
	Role       record.Role
	Provenance IssuerProvenance
}

func (i TrustedIssuer) ValidFor(role record.Role) bool {
	return i.Tenant != "" && i.Role == role && (i.Provenance == PinnedTLSLogin || i.Provenance == AuthenticatedAdmission)
}
