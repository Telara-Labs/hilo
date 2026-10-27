package sig

import (
	"errors"
	"reflect"
	"testing"
)

// Standard-library equivalents retain the gateway oracles without adding a
// test-framework dependency to the shared contract module.
func parityFail(t testing.TB, message string, extra ...any) {
	t.Helper()
	t.Fatalf("%s %v", message, extra)
}
func parityNoError(t testing.TB, err error, extra ...any) {
	t.Helper()
	if err != nil {
		parityFail(t, "unexpected error", append([]any{err}, extra...)...)
	}
}
func parityErrorIs(t testing.TB, err, want error, extra ...any) {
	t.Helper()
	if !errors.Is(err, want) {
		parityFail(t, "error mismatch", append([]any{err, want}, extra...)...)
	}
}
func parityEqual(t testing.TB, want, got any, extra ...any) {
	t.Helper()
	if !reflect.DeepEqual(want, got) {
		parityFail(t, "values differ", append([]any{want, got}, extra...)...)
	}
}
func parityNil(t testing.TB, got any, extra ...any) {
	t.Helper()
	if got == nil {
		return
	}
	v := reflect.ValueOf(got)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if v.IsNil() {
			return
		}
	}
	parityFail(t, "expected nil", extra...)
}
func parityEmpty(t testing.TB, got any, extra ...any) {
	t.Helper()
	if got == nil {
		return
	}
	v := reflect.ValueOf(got)
	switch v.Kind() {
	case reflect.Map, reflect.Slice, reflect.String, reflect.Array, reflect.Chan:
		if v.Len() == 0 {
			return
		}
	default:
		if v.IsZero() {
			return
		}
	}
	parityFail(t, "expected empty", extra...)
}
func parityZero(t testing.TB, got any, extra ...any) {
	t.Helper()
	if got != nil && !reflect.ValueOf(got).IsZero() {
		parityFail(t, "expected zero", extra...)
	}
}
func parityLen(t testing.TB, got any, want int, extra ...any) {
	t.Helper()
	if reflect.ValueOf(got).Len() != want {
		parityFail(t, "length mismatch", extra...)
	}
}
func parityNumber(v any) float64 {
	n := reflect.ValueOf(v)
	switch n.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return float64(n.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return float64(n.Uint())
	default:
		return n.Float()
	}
}
func parityLess(t testing.TB, got, want any, extra ...any) {
	t.Helper()
	if parityNumber(got) >= parityNumber(want) {
		parityFail(t, "expected less", extra...)
	}
}
func parityPositive(t testing.TB, got any, extra ...any) {
	t.Helper()
	if parityNumber(got) <= 0 {
		parityFail(t, "expected positive", extra...)
	}
}
func parityTrue(t testing.TB, got bool, extra ...any) {
	t.Helper()
	if !got {
		parityFail(t, "expected true", extra...)
	}
}
func parityFalse(t testing.TB, got bool, extra ...any) {
	t.Helper()
	if got {
		parityFail(t, "expected false", extra...)
	}
}
func paritySame(t testing.TB, want, got any, extra ...any) {
	t.Helper()
	if reflect.ValueOf(want).Pointer() != reflect.ValueOf(got).Pointer() {
		parityFail(t, "expected same pointer", extra...)
	}
}
func parityNotSame(t testing.TB, want, got any, extra ...any) {
	t.Helper()
	if reflect.ValueOf(want).Pointer() == reflect.ValueOf(got).Pointer() {
		parityFail(t, "expected distinct pointer", extra...)
	}
}
