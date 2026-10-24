package record

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"sort"
)

// OperationTokens is pure receiver-issued identity state. The adapter commits
// its updated snapshot with FULL durability before releasing tokens or outcomes.
// Never expose a candidate pool before the issuance transaction commits.
var ErrOperationConsumed = errors.New("prior_operation_committed")

type OperationTokens struct {
	issued   map[string]string
	consumed map[string]bool
}

func NewOperationTokens() *OperationTokens {
	return &OperationTokens{issued: map[string]string{}, consumed: map[string]bool{}}
}
func (p *OperationTokens) Clone() *OperationTokens {
	q := NewOperationTokens()
	for t, c := range p.issued {
		q.issued[t] = c
	}
	for t, c := range p.consumed {
		q.consumed[t] = c
	}
	return q
}
func (p *OperationTokens) Issue(credential string) ([]string, error) {
	return p.issue(credential, rand.Reader)
}
func (p *OperationTokens) issue(credential string, entropy io.Reader) ([]string, error) {
	if credential == "" {
		return nil, errors.New("credential required")
	}
	unused := []string{}
	for t, c := range p.issued {
		if c == credential && !p.consumed[t] {
			unused = append(unused, t)
		}
	}
	sort.Strings(unused)
	if len(unused) > 120 {
		return unused, nil
	}
	pending := []string{}
	seen := map[string]bool{}
	for i := 0; i < 8; i++ {
		var secret [16]byte
		if _, err := io.ReadFull(entropy, secret[:]); err != nil {
			clear(secret[:])
			if len(unused) > 0 {
				return unused, nil
			}
			return nil, errors.New("operation token entropy unavailable")
		}
		token := "op1:" + hex.EncodeToString(secret[:])
		clear(secret[:])
		// Collision holds the whole batch rather than selecting caller-controlled entropy.
		if _, exists := p.issued[token]; exists || seen[token] {
			if len(unused) > 0 {
				return unused, nil
			}
			return nil, errors.New("operation token collision")
		}
		seen[token] = true
		pending = append(pending, token)
	}
	for _, t := range pending {
		p.issued[t] = credential
	}
	return pending, nil
}
func (p *OperationTokens) Resolve(credential, token string) (string, error) {
	if !ValidCallerOpID(token) || credential == "" || p.issued[token] != credential {
		return "", errors.New("unissued operation token")
	}
	return HE("op-supplied", credential, token)
}

// Consume must commit atomically with the first accepted mutation/call/outcome.
// A consumed token resolves for retries but never returns to an unused pool.
func (p *OperationTokens) Consume(credential, token string) error {
	if _, err := p.Resolve(credential, token); err != nil {
		return err
	}
	if p.consumed[token] {
		return ErrOperationConsumed
	}
	p.consumed[token] = true
	return nil
}

// IssuedOperationToken is content-free receiver settlement. Only an
// authenticated recovered local ledger may supply this snapshot; initialize
// parameters, clientInfo and bundles are never restore authorities.
type IssuedOperationToken struct {
	Token      string `json:"token"`
	Credential string `json:"credential"`
	Consumed   bool   `json:"consumed"`
}

func (p *OperationTokens) Snapshot() []IssuedOperationToken {
	out := []IssuedOperationToken{}
	for token, credential := range p.issued {
		out = append(out, IssuedOperationToken{Token: token, Credential: credential, Consumed: p.consumed[token]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Token < out[j].Token })
	return out
}
func RestoreOperationTokens(rows []IssuedOperationToken) (*OperationTokens, error) {
	p := NewOperationTokens()
	unused := map[string]int{}
	for _, row := range rows {
		if !ValidCallerOpID(row.Token) || row.Credential == "" {
			return nil, errors.New("invalid issuance snapshot")
		}
		if _, ok := p.issued[row.Token]; ok {
			return nil, errors.New("duplicate issued token")
		}
		p.issued[row.Token] = row.Credential
		p.consumed[row.Token] = row.Consumed
		if !row.Consumed {
			unused[row.Credential]++
			if unused[row.Credential] > 128 {
				return nil, errors.New("unused issuance bound")
			}
		}
	}
	return p, nil
}
