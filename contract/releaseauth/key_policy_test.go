package releaseauth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func syntheticPolicyKey(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("unit-only-release-key-policy-" + label))
	return ed25519.NewKeyFromSeed(seed[:])
}
func historicalPair(build, sums []byte) historicalManifest {
	b, s := sha256.Sum256(build), sha256.Sum256(sums)
	return historicalManifest{hex.EncodeToString(b[:]), hex.EncodeToString(s[:])}
}

func TestVerificationPolicyPreservesCompiledPinWithoutRotation(t *testing.T) {
	public, err := PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	p, err := compiledVerificationPolicy()
	if err != nil || !bytes.Equal(p.active, public) || len(p.history) != 0 {
		t.Fatal("default policy changed active or historical authority")
	}
	other := syntheticPolicyKey("unapproved")
	defer clear(other)
	build, sums := []byte("historical build"), []byte("historical sums")
	if p.verify(build, sums, ed25519.Sign(other, payload(build, sums))) == nil {
		t.Fatal("unapproved hardware key became trusted")
	}
}

func TestVerificationPolicyHistoricalExactBytesAndDefensiveCopies(t *testing.T) {
	active, old := syntheticPolicyKey("active"), syntheticPolicyKey("old")
	defer clear(active)
	defer clear(old)
	for _, family := range []string{hiloArtifactPrefix, legacyArtifactPrefix} {
		t.Run(family, func(t *testing.T) {
			build, sums := []byte("historical exact BUILD\n"), testSums(family)
			history := []historicalAuthority{{old.Public().(ed25519.PublicKey), []historicalManifest{historicalPair(build, sums)}}}
			public := active.Public().(ed25519.PublicKey)
			p, err := newVerificationPolicy(public, history)
			if err != nil {
				t.Fatal(err)
			}
			clear(public)
			clear(history[0].Public)
			history[0].Manifests[0].Build = "changed"
			if p.verify(build, sums, ed25519.Sign(old, payload(build, sums))) != nil {
				t.Fatal("exact old artifact lost verification or caller mutated policy")
			}
			changed := append(bytes.Clone(build), 'x')
			if p.verify(changed, sums, ed25519.Sign(old, payload(changed, sums))) == nil {
				t.Fatal("old key gained new manifest authority")
			}
			changedSums := append(bytes.Clone(sums), 'x')
			if p.verify(build, changedSums, ed25519.Sign(old, payload(build, changedSums))) == nil {
				t.Fatal("old key gained changed artifact authority")
			}
			if p.verify(changed, sums, ed25519.Sign(active, payload(changed, sums))) != nil {
				t.Fatal("active key refused ordinary new release")
			}
			wrongDomain := append([]byte("hilo-release-v1\x00"), build...)
			wrongDomain = append(wrongDomain, 0)
			wrongDomain = append(wrongDomain, sums...)
			if p.verify(build, sums, ed25519.Sign(old, wrongDomain)) == nil {
				t.Fatal("historical domain changed")
			}
			if p.verify(build, sums, make([]byte, 63)) == nil {
				t.Fatal("short signature accepted")
			}
		})
	}
}

func TestVerificationPolicyRejectsAmbiguousUnboundedAuthorities(t *testing.T) {
	active, old := syntheticPolicyKey("active"), syntheticPolicyKey("old")
	defer clear(active)
	defer clear(old)
	pair := historicalPair([]byte("build"), []byte("sums"))
	base := historicalAuthority{old.Public().(ed25519.PublicKey), []historicalManifest{pair}}
	cases := []struct {
		public  ed25519.PublicKey
		history []historicalAuthority
	}{
		{nil, nil}, {active.Public().(ed25519.PublicKey), []historicalAuthority{{nil, []historicalManifest{pair}}}},
		{active.Public().(ed25519.PublicKey), []historicalAuthority{{active.Public().(ed25519.PublicKey), []historicalManifest{pair}}}},
		{active.Public().(ed25519.PublicKey), []historicalAuthority{base, base}},
		{active.Public().(ed25519.PublicKey), []historicalAuthority{{base.Public, []historicalManifest{pair, pair}}}},
		{active.Public().(ed25519.PublicKey), []historicalAuthority{{base.Public, []historicalManifest{{"nothex", pair.Sums}}}}},
		{active.Public().(ed25519.PublicKey), []historicalAuthority{{base.Public, nil}}},
		{active.Public().(ed25519.PublicKey), make([]historicalAuthority, 5)},
		{active.Public().(ed25519.PublicKey), []historicalAuthority{{base.Public, make([]historicalManifest, 257)}}},
	}

	// Every row is otherwise valid and unique; this reaches the aggregate513 cap.
	var excessive []historicalAuthority
	for group, count := range []int{256, 256, 1} {
		key := syntheticPolicyKey("aggregate-" + string(rune('a'+group)))
		a := historicalAuthority{Public: key.Public().(ed25519.PublicKey)}
		for i := 0; i < count; i++ {
			a.Manifests = append(a.Manifests, historicalPair([]byte{byte(group), byte(i)}, []byte("exact sums")))
		}
		excessive = append(excessive, a)
		clear(key)
	}
	cases = append(cases, struct {
		public  ed25519.PublicKey
		history []historicalAuthority
	}{active.Public().(ed25519.PublicKey), excessive})
	for i, c := range cases {
		if _, err := newVerificationPolicy(c.public, c.history); err == nil {
			t.Fatalf("invalid policy %d accepted", i)
		}
	}
}
