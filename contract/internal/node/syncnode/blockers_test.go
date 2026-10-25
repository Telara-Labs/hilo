package syncnode

import (
	"context"
	"errors"
	"testing"
	"time"
)

// A real round against a hosted endpoint without the control log persists the
// failure; Status and Blockers report it without contacting the network.
func TestBlockersReportHostedLogUnavailable(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	if got := Blockers(mustStatus(t, w.dir), time.Now()); len(got) != 0 {
		t.Fatal("unconfigured sync reported blockers", got)
	}
	w.task(1, repoA, "active")
	w.enroll()
	wk := w.worker()
	w.selectRepo(wk, repoA)
	w.hosted.helloStatus = 404
	if err := wk.Round(ctx); !errors.Is(err, ErrHostedLog) {
		t.Fatal(err)
	}
	r := mustStatus(t, w.dir)
	got := Blockers(r, time.Now())
	if r.LastError != ErrHostedLog.Error() || len(got) != 1 || got[0] != "sync_hosted_log_unavailable" {
		t.Fatalf("blockers %v from %+v", got, r)
	}
	if err := SetEnabled(w.dir, false); err != nil {
		t.Fatal(err)
	}
	got = Blockers(mustStatus(t, w.dir), time.Unix(r.GrantExpiresAt, 0))
	if len(got) != 3 || got[0] != "disabled" || got[1] != "grant_expired" || got[2] != "sync_hosted_log_unavailable" {
		t.Fatal("disabled and expired", got)
	}
}

func mustStatus(t *testing.T, dir string) StatusReport {
	t.Helper()
	r, err := Status(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
