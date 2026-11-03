//go:build e2e && darwin

package clients_test

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"

	"github.com/Telara-Labs/hilo/contract/internal/node/install"
)

func verifyShimImage(cfg installedConfig, exe string) error {
	v, err := install.VerifiedExecutable(cfg.Install)
	if err != nil {
		return errors.New("shim install receipt verification failed")
	}
	defer v.Close()
	// Matching bytes at another path are deliberately insufficient for peer proof.
	if exe != v.Path {
		return errors.New("shim executable differs from install receipt")
	}
	return nil
}

func captureACK(ctx context.Context, data, client string, minimum int) error {
	files, err := os.ReadDir(filepath.Join(data, "spool", client, "new"))
	if err != nil || len(files) != 0 {
		return errors.New("capture signal remains unACKed")
	}
	u := url.URL{Scheme: "file", Path: filepath.Join(data, "memory.sqlite"), RawQuery: "mode=ro"}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	for _, table := range []string{"spool_done", "spool_announcement"} {
		var count int
		if err = db.QueryRowContext(ctx, "SELECT count(*) FROM "+table+" WHERE client=?", client).Scan(&count); err != nil {
			return err
		}
		if count < minimum {
			return errors.New("capture ACK has no durable admission receipt")
		}
	}
	return nil
}
