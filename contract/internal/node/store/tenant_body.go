package store

import (
	"reflect"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/disclosuretext"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/localpolicy"
)

// bodyPolicyAllowed walks the closed, decoded record schema rather than the
// renderer's display inventory. All string values and dynamic map keys are
// retained data, including non-displayed evidence and opaque references. Static
// schema member names are not data. Signed bodies must already satisfy policy;
// changing them here would invalidate their seal.
func bodyPolicyAllowed(body any, overlay localpolicy.Overlay) bool {
	work := &disclosuretext.WorkBudget{}
	normalized := func(s string) (string, bool) {
		n, _, err := disclosuretext.NormalizePolicyValue(s, work)
		return n, err == nil && overlay.Text(s) == s && overlay.Text(n) == n
	}
	var allowed func(reflect.Value) bool
	allowed = func(v reflect.Value) bool {
		switch v.Kind() {
		case reflect.Invalid:
			return true
		case reflect.Pointer, reflect.Interface:
			return v.IsNil() || allowed(v.Elem())
		case reflect.Struct:
			for i := 0; i < v.NumField(); i++ {
				if !allowed(v.Field(i)) {
					return false
				}
			}
		case reflect.Slice, reflect.Array:
			for i := 0; i < v.Len(); i++ {
				if !allowed(v.Index(i)) {
					return false
				}
			}
		case reflect.Map:
			it := v.MapRange()
			for it.Next() {
				if !allowed(it.Key()) || !allowed(it.Value()) {
					return false
				}
				// Dynamic names may themselves classify a value as secret even
				// when its bytes do not match a token pattern (for example password).
				if it.Key().Kind() == reflect.String && it.Value().Kind() == reflect.String {
					value := it.Value().String()
					if overlay.Argument(it.Key().String(), value) != value {
						return false
					}
					name, ok := normalized(it.Key().String())
					n, valueOK := normalized(value)
					if !ok || !valueOK || overlay.Argument(name, n) != n {
						return false
					}
				}
			}
		case reflect.String:
			_, ok := normalized(v.String())
			return ok
		case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Float32, reflect.Float64:
			return true
		default:
			// Future unsupported schema types fail closed.
			return false
		}
		return true
	}
	return allowed(reflect.ValueOf(body))
}
