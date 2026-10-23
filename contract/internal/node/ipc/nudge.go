package ipc

import (
	"context"
	"time"
)

// Nudge is a disposable wake-up. One 50 ms budget covers connect and write;
// success never represents durable capture or spool admission.
func Nudge(parent context.Context, p Paths, client string) error {
	ctx, cancel := context.WithTimeout(parent, 50*time.Millisecond)
	defer cancel()
	c, e := Dial(ctx, p)
	if e != nil {
		return e
	}
	defer c.Close()
	deadline, _ := ctx.Deadline()
	if e = c.SetDeadline(deadline); e != nil {
		return e
	}
	return WriteFrame(c, struct {
		T      string `json:"t"`
		V      int    `json:"v"`
		Client string `json:"client"`
	}{"nudge", 1, client})
}
