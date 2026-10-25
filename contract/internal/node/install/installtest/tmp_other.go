//go:build !(darwin || linux)

package installtest

// UsePrivateTempRoot keeps the platform temporary directory; only the Unix
// installer walk refuses shared temporary ancestors.
func UsePrivateTempRoot() (func(), error) { return func() {}, nil }
