package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/Telara-Labs/hilo/contract/internal/node/ipc"
	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/transport"
)

// BundleExportLock is the lock an exporter holds for the whole life of one
// registered export, from before registration until its staging copy is
// published or destroyed. The erasure lifecycle reads a free lock as an
// exporter that no longer runs.
func BundleExportLock(dir, token string) string {
	return filepath.Join(dir, "bundle-export-"+token+".lock")
}

// RegisterBundleExport selects a bundle under the store writer and, in the
// same transaction, registers the in-flight export with the erasure
// lifecycle: its staging path, the identity of the selected content and
// every data or variant source id it carries, and the exact signed bytes of
// every variant. The caller must already hold BundleExportLock(dir, token).
// Governed session and task heads travel only as fresh push-metadata
// variants signed by signer, under the complete current authorization.
func (s *Store) RegisterBundleExport(ctx context.Context, token, staging string, ids []string, signer ControlSigner) (BundleSelection, error) {
	if !record.IsKeyID(token) || !filepath.IsAbs(staging) || filepath.Clean(staging) != staging {
		return BundleSelection{}, failure("invalid_request")
	}
	selected, err := bundleIDs(ids)
	if err != nil {
		return BundleSelection{}, err
	}
	var out BundleSelection
	err = s.write(ctx, func() error {
		d, err := s.load(ctx)
		if err != nil {
			return err
		}
		if d.blocked {
			return d.blockedError()
		}
		sel, meta, err := s.selectLocked(ctx, d, selected, variantSign, signer)
		if err != nil {
			return err
		}
		if _, err = s.conn.ExecContext(ctx, "INSERT INTO bundle_export(id,staging,digest) VALUES(?,?,?)", token, staging, meta.digest()); err != nil {
			return failure("storage_error")
		}
		for _, id := range meta.sources {
			if _, err = s.conn.ExecContext(ctx, "INSERT OR IGNORE INTO bundle_export_item VALUES(?,?)", token, id); err != nil {
				return failure("storage_error")
			}
		}
		// The exact signed variant bytes the staging copy will carry are
		// registered with the export, so publication revalidates those
		// frozen bytes rather than a fresh build.
		for _, v := range meta.variants {
			if err = s.associateRepositoryRecord(ctx, v.source, v.rec.AdvisoryID); err != nil {
				return err
			}
			sigs, err := json.Marshal(v.rec.Sigs)
			if err != nil {
				return failure("invalid_record")
			}
			if _, err = s.conn.ExecContext(ctx, "INSERT INTO bundle_export_variant(export,source,id,header,body,sigs) VALUES(?,?,?,?,?,?)", token, v.source, v.rec.AdvisoryID, v.rec.HeaderJCS, v.rec.BodyJCS, sigs); err != nil {
				return failure("storage_error")
			}
		}
		out = sel
		return nil
	})
	if err != nil {
		return BundleSelection{}, err
	}
	return out, nil
}

// PublishBundleExport serializes final publication against current tombs,
// policy and keys. Under the store writer it requires the registration to be
// present and not cancelled, every registered signed variant to be permitted
// as frozen by the complete current authorization, and the same selection
// evaluated now to have exactly the registered identity: the same keyring,
// controls, facts, data and byte-identical variants under current redaction
// and authorization. Only then does publish run, still under the writer, so
// no erasure, key or policy change can interleave. Otherwise the staging copy
// is destroyed and bundle_invalidated returned. The registration is removed
// either way.
func (s *Store) PublishBundleExport(ctx context.Context, token string, ids []string, publish func() error) error {
	selected, err := bundleIDs(ids)
	if err != nil {
		return err
	}
	var outcome error
	err = s.write(ctx, func() error {
		var staging, digest string
		var cancelled bool
		err := s.conn.QueryRowContext(ctx, "SELECT staging,digest,cancelled FROM bundle_export WHERE id=?", token).Scan(&staging, &digest, &cancelled)
		if err == sql.ErrNoRows {
			outcome = failure("bundle_invalidated")
			return nil
		}
		if err != nil {
			return failure("storage_error")
		}
		current := !cancelled
		if current {
			d, err := s.load(ctx)
			if err != nil {
				return err
			}
			if d.blocked {
				current = false
			} else {
				key, ok, err := s.revalidateFrozenVariants(ctx, d, token)
				if err != nil {
					return err
				}
				current = ok
				if current {
					var check ControlSigner
					if key != "" {
						check = variantKey(key)
					}
					_, meta, err := s.selectLocked(ctx, d, selected, variantCheck, check)
					if err != nil {
						return err
					}
					current = meta.digest() == digest
				}
			}
		}
		if current {
			outcome = publish()
		} else {
			outcome = failure("bundle_invalidated")
		}
		if outcome != nil {
			if err := os.Remove(staging); err != nil && !errors.Is(err, os.ErrNotExist) {
				return failure("storage_error")
			}
		}
		return s.forgetBundleExport(ctx, token)
	})
	if err != nil {
		return err
	}
	return outcome
}

// AbandonBundleExport destroys the staging copy of an export that will not
// be published and removes its registration.
func (s *Store) AbandonBundleExport(ctx context.Context, token string) error {
	return s.write(ctx, func() error {
		var staging string
		err := s.conn.QueryRowContext(ctx, "SELECT staging FROM bundle_export WHERE id=?", token).Scan(&staging)
		if err == sql.ErrNoRows {
			return nil
		}
		if err != nil {
			return failure("storage_error")
		}
		if err = os.Remove(staging); err != nil && !errors.Is(err, os.ErrNotExist) {
			return failure("storage_error")
		}
		return s.forgetBundleExport(ctx, token)
	})
}

// variantKey names the key a registered variant was signed by, so a
// check-mode selection rebuilds the exact unsigned bytes. It never signs.
type variantKey string

func (k variantKey) KeyID() string { return string(k) }
func (variantKey) SignRecordID(string) (record.Signature, error) {
	return record.Signature{}, failure("signing_unavailable")
}

// revalidateFrozenVariants checks every signed variant registered with an
// export, as frozen, under the complete current authorization: each must
// still parse to its registered id as a push-metadata variant of its
// registered source, carry its registered signature, and be permitted in a
// bundle by the current policy, including its redaction shapes. It returns
// the single key the variants were signed by, empty when there are none.
func (s *Store) revalidateFrozenVariants(ctx context.Context, d *databaseState, token string) (string, bool, error) {
	rows, err := s.conn.QueryContext(ctx, "SELECT source,id,header,body,sigs FROM bundle_export_variant WHERE export=? ORDER BY source", token)
	if err != nil {
		return "", false, failure("storage_error")
	}
	defer rows.Close()
	key, ok := "", true
	for rows.Next() {
		var source, id string
		var header, body, raw []byte
		if rows.Scan(&source, &id, &header, &body, &raw) != nil {
			return "", false, failure("storage_error")
		}
		var sigs []record.Signature
		r, err := record.Parse(header, body, id)
		if err != nil || json.Unmarshal(raw, &sigs) != nil || len(sigs) != 1 {
			ok = false
			continue
		}
		h := r.Header
		if h.Red.Profile != record.ProfilePushMetadata || h.Links.Origin != source || r.Body == nil || sigs[0].KeyID != h.Author.KeyID || key != "" && key != h.Author.KeyID {
			ok = false
			continue
		}
		key = h.Author.KeyID
		if !transport.BundlePolicyAllowed(r, d.bundleAuthorization(r)) {
			ok = false
		}
	}
	if rows.Err() != nil {
		return "", false, failure("storage_error")
	}
	return key, ok, nil
}

func (s *Store) forgetBundleExport(ctx context.Context, token string) error {
	if _, err := s.conn.ExecContext(ctx, "DELETE FROM bundle_export_variant WHERE export=?", token); err != nil {
		return failure("storage_error")
	}
	if _, err := s.conn.ExecContext(ctx, "DELETE FROM bundle_export_item WHERE export=?", token); err != nil {
		return failure("storage_error")
	}
	if _, err := s.conn.ExecContext(ctx, "DELETE FROM bundle_export WHERE id=?", token); err != nil {
		return failure("storage_error")
	}
	return nil
}

type inflightExport struct {
	id, staging string
	cancelled   bool
}

// reconcileBundleExports runs under the erasure fence before any clean scrub
// receipt. It enumerates every registered in-flight export, including ones
// whose exporter crashed. An export carrying a record that is no longer live
// with its body is cancelled. While its exporter still runs, the erasure
// stays pending: that exporter will find the cancellation when it tries to
// publish, and destroys its staging copy. Once no exporter holds the lock,
// the staging copy is destroyed here and the registration removed.
func (s *Store) reconcileBundleExports(ctx context.Context, d *databaseState) (bool, error) {
	rows, err := s.conn.QueryContext(ctx, "SELECT id,staging,cancelled FROM bundle_export ORDER BY id")
	if err != nil {
		return false, failure("storage_error")
	}
	var exports []inflightExport
	for rows.Next() {
		var e inflightExport
		if rows.Scan(&e.id, &e.staging, &e.cancelled) != nil {
			rows.Close()
			return false, failure("storage_error")
		}
		exports = append(exports, e)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return false, failure("storage_error")
	}
	pending := false
	for _, e := range exports {
		affected := e.cancelled
		items, err := s.conn.QueryContext(ctx, "SELECT id FROM bundle_export_item WHERE export=?", e.id)
		if err != nil {
			return false, failure("storage_error")
		}
		for items.Next() {
			var id string
			if items.Scan(&id) != nil {
				items.Close()
				return false, failure("storage_error")
			}
			if x := d.byID[id]; x == nil || x.state != "live" || x.rec.Body == nil {
				affected = true
			}
		}
		err = items.Err()
		items.Close()
		if err != nil {
			return false, failure("storage_error")
		}
		lockPath := BundleExportLock(s.opts.Dir, e.id)
		lock, err := ipc.Lock(lockPath)
		if errors.Is(err, ipc.ErrBusy) {
			if affected {
				if _, err = s.conn.ExecContext(ctx, "UPDATE bundle_export SET cancelled=1 WHERE id=?", e.id); err != nil {
					return false, failure("storage_error")
				}
				pending = true
			}
			continue
		}
		if err != nil {
			// The exporter's state cannot be established: never a clean receipt.
			pending = pending || affected
			continue
		}
		rmErr := os.Remove(e.staging)
		if rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
			lock.Close()
			pending = pending || affected
			continue
		}
		if err = s.forgetBundleExport(ctx, e.id); err != nil {
			lock.Close()
			return false, err
		}
		lock.Close()
		os.Remove(lockPath)
	}
	return pending, nil
}

// ControlReview is the content-free description of one carried control
// whose effect is unbounded and so needs the receiving owner's local
// confirmation before a bundle may apply it.
type ControlReview struct {
	ID       string `json:"id"`
	IDs      int    `json:"ids"`
	Events   int    `json:"events"`
	Tasks    int    `json:"tasks"`
	Sessions int    `json:"sessions"`
	LIDs     int    `json:"lids"`
	Sources  int    `json:"sources"`
}

// ReviewBundleControls lists the carried erasures not already admitted here
// whose selectors have unbounded future effect: any event, task, session,
// LID or source selector, even with zero current matches.
func (s *Store) ReviewBundleControls(ctx context.Context, controls []SignedRecord) ([]ControlReview, error) {
	if len(controls) > 16384 {
		return nil, failure("invalid_request")
	}
	var out []ControlReview
	err := s.write(ctx, func() error {
		d, err := s.load(ctx)
		if err != nil {
			return err
		}
		out = nil
		for _, item := range controls {
			r, _, err := parse(item)
			if err != nil {
				return err
			}
			b, ok := r.Body.(*record.ErasureBody)
			if !ok || d.byID[r.ID] != nil {
				continue
			}
			sel := b.Selectors
			if len(sel.Events)+len(sel.Tasks)+len(sel.Sessions)+len(sel.LIDs)+len(sel.Sources) == 0 {
				continue
			}
			out = append(out, ControlReview{ID: r.ID, IDs: len(sel.IDs), Events: len(sel.Events), Tasks: len(sel.Tasks), Sessions: len(sel.Sessions), LIDs: len(sel.LIDs), Sources: len(sel.Sources)})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
