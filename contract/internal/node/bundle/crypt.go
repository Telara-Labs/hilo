package bundle

import (
	"bytes"
	"io"
	"strings"

	"filippo.io/age"

	nodesync "github.com/Telara-Labs/telara-memory/contract/internal/node/sync"
)

// ScryptWorkFactor is the scrypt cost (log2 N) of new backups. MaxScryptWorkFactor
// caps the cost a restore will spend on an untrusted file.
var (
	ScryptWorkFactor    = 18
	MaxScryptWorkFactor = 22
)

// maxFrame is the raw-block zstd frame of a MaxBytes plaintext: a 9-byte
// header plus a 3-byte header per 128 KiB block.
const maxFrame = MaxBytes + 9 + 3*(MaxBytes/(128<<10)+1)

// MaxCiphertext bounds an encrypted bundle file before it is read: the frame,
// age's 16-byte tag per 64 KiB chunk, its nonce and a bounded header.
const MaxCiphertext = maxFrame + 16*(maxFrame/(64<<10)+1) + 16 + 1<<20

// MinPassphrase is the shortest accepted backup passphrase, in bytes.
const MinPassphrase = 12

// SealTransfer encrypts plaintext to the given X25519 export key recipients.
// There is no plaintext or mixed-recipient-type form.
func SealTransfer(plaintext []byte, recipients []string) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, ErrRecipient
	}
	var rs []age.Recipient
	seen := map[string]bool{}
	for _, s := range recipients {
		r, err := age.ParseX25519Recipient(s)
		if err != nil || seen[s] {
			return nil, ErrRecipient
		}
		seen[s] = true
		rs = append(rs, r)
	}
	return seal(plaintext, rs...)
}

// SealBackup encrypts plaintext to a passphrase as the sole scrypt recipient.
func SealBackup(plaintext []byte, passphrase string) ([]byte, error) {
	if len(passphrase) < MinPassphrase || len(passphrase) > 1024 {
		return nil, ErrPassphrase
	}
	r, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return nil, ErrPassphrase
	}
	r.SetWorkFactor(ScryptWorkFactor)
	return seal(plaintext, r)
}

func seal(plaintext []byte, rs ...age.Recipient) ([]byte, error) {
	if len(plaintext) > MaxBytes {
		return nil, ErrTooLarge
	}
	frame := nodesync.RawZstd(plaintext)
	defer clear(frame)
	var out bytes.Buffer
	w, err := age.Encrypt(&out, rs...)
	if err != nil {
		return nil, ErrRecipient
	}
	if _, err = w.Write(frame); err != nil {
		return nil, ErrInvalid
	}
	if err = w.Close(); err != nil {
		return nil, ErrInvalid
	}
	return out.Bytes(), nil
}

// recordingIdentity reports every recipient stanza type the file carries so
// the mode is checked from the encryption itself, never from a file label.
type recordingIdentity struct {
	inner age.Identity
	kinds *[]string
}

func (r recordingIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	if len(*r.kinds) == 0 {
		for _, s := range stanzas {
			*r.kinds = append(*r.kinds, strings.ToLower(s.Type))
		}
	}
	return r.inner.Unwrap(stanzas)
}

// OpenTransfer decrypts a transfer bundle with this device's export key.
func OpenTransfer(ciphertext []byte, id *age.X25519Identity) ([]byte, []string, error) {
	if id == nil {
		return nil, nil, ErrExportKey
	}
	return open(ciphertext, id)
}

// OpenBackup decrypts a backup bundle with its passphrase. age itself refuses
// a scrypt stanza that is not the only recipient.
func OpenBackup(ciphertext []byte, passphrase string) ([]byte, []string, error) {
	if passphrase == "" || len(passphrase) > 1024 {
		return nil, nil, ErrPassphrase
	}
	id, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return nil, nil, ErrPassphrase
	}
	id.SetMaxWorkFactor(MaxScryptWorkFactor)
	return open(ciphertext, id)
}

func open(ciphertext []byte, id age.Identity) ([]byte, []string, error) {
	if len(ciphertext) > MaxCiphertext {
		return nil, nil, ErrTooLarge
	}
	var kinds []string
	r, err := age.Decrypt(bytes.NewReader(ciphertext), recordingIdentity{id, &kinds})
	if err != nil {
		return nil, kinds, ErrDecrypt
	}
	frame, err := io.ReadAll(io.LimitReader(r, maxFrame+1))
	defer clear(frame)
	if err != nil {
		return nil, kinds, ErrDecrypt
	}
	if len(frame) > maxFrame {
		return nil, kinds, ErrTooLarge
	}
	plaintext, err := nodesync.ReadRawZstd(frame, MaxBytes)
	if err != nil {
		return nil, kinds, ErrInvalid
	}
	return plaintext, kinds, nil
}
