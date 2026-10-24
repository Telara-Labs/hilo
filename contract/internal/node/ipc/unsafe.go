package ipc

import (
	"fmt"
	"os"
)

// unsafePath keeps the stable public sentinel while retaining the failing
// operation, component and rule. The detail remains available as a PathError.
func unsafePath(op, path, rule string, cause error) error {
	detail := fmt.Errorf("%s", rule)
	if cause != nil {
		// Do not make a refused path classify as absent, existing or busy.
		// Those classifications have control-flow meaning to callers. Preserve
		// the prior sentinel-only classification and retain the cause as text.
		detail = fmt.Errorf("%s: %v", rule, cause)
	}
	return fmt.Errorf("%w: %w", ErrUnsafe, &os.PathError{Op: op, Path: path, Err: detail})
}
