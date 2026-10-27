package record

import (
	"encoding/json"
	"fmt"
	"github.com/Telara-Labs/hilo/contract/jcs"
	"reflect"
	"strings"
)

// CheckClosedObject validates exact case-sensitive fields, required presence,
// JSON types, no nulls, safe integral ranges and list limits BEFORE decoding.
// The target is a schema shape only. Optional omission is checked against the
// original bytes by Parse, never by silently normalizing a received object.
func CheckClosedObject(raw []byte, target any) error {
	if _, err := jcs.CanonicalizeRecord(raw); err != nil {
		return err
	}
	t := reflect.TypeOf(target)
	if t == nil {
		return fmt.Errorf("schema required")
	}
	return checkShape(raw, t, "")
}
func checkShape(raw json.RawMessage, t reflect.Type, field string) error {
	if string(raw) == "null" || len(raw) == 0 {
		return fmt.Errorf("null or missing field")
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Struct:
		var obj map[string]json.RawMessage
		if len(raw) == 0 || raw[0] != '{' || json.Unmarshal(raw, &obj) != nil {
			return fmt.Errorf("object required")
		}
		fields := map[string]reflect.StructField{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			tag := strings.Split(f.Tag.Get("json"), ",")
			if tag[0] == "-" || f.PkgPath != "" {
				continue
			}
			name := tag[0]
			if name == "" {
				name = f.Name
			}
			fields[name] = f
			if len(tag) == 1 {
				if _, ok := obj[name]; !ok {
					return fmt.Errorf("required field missing")
				}
			}
		}
		for name, value := range obj {
			f, ok := fields[name]
			if !ok {
				return fmt.Errorf("unknown field")
			}
			ft := f.Type
			for ft.Kind() == reflect.Pointer {
				ft = ft.Elem()
			}
			if strings.Contains(f.Tag.Get("json"), ",") && ft.Kind() == reflect.Struct && string(value) == "{}" {
				return fmt.Errorf("empty optional object")
			}
			if err := checkShape(value, f.Type, name); err != nil {
				return err
			}
		}
	case reflect.Slice:
		if raw[0] != '[' {
			return fmt.Errorf("array required")
		}
		var xs []json.RawMessage
		if json.Unmarshal(raw, &xs) != nil || len(xs) > 8192 {
			return fmt.Errorf("array limit")
		}
		for _, x := range xs {
			if err := checkShape(x, t.Elem(), field); err != nil {
				return err
			}
		}
	case reflect.Map:
		if raw[0] != '{' {
			return fmt.Errorf("map required")
		}
		var xs map[string]json.RawMessage
		if json.Unmarshal(raw, &xs) != nil || len(xs) > 8192 {
			return fmt.Errorf("map limit")
		}
		for _, x := range xs {
			if err := checkShape(x, t.Elem(), field); err != nil {
				return err
			}
		}
	case reflect.String:
		var v string
		if raw[0] != '"' || json.Unmarshal(raw, &v) != nil {
			return fmt.Errorf("string required")
		}
	case reflect.Bool:
		var v bool
		if json.Unmarshal(raw, &v) != nil {
			return fmt.Errorf("bool required")
		}
	case reflect.Int, reflect.Int64, reflect.Int32, reflect.Uint, reflect.Uint64:
		var v int64
		min := int64(0)
		if field == "settled_through" {
			min = -1
		}
		if json.Unmarshal(raw, &v) != nil || v < min || v > jcs.MaxSafeInteger {
			return fmt.Errorf("integer range")
		}
	default:
		return fmt.Errorf("unsupported schema shape")
	}
	return nil
}
