// Package embedding contains experimental local vector arithmetic. It does not
// load a model, authorize content, or persist projections.
package embedding

import (
	"fmt"
	"math"
)

const Dimensions = 256

// EncodingID must be bound to a model digest and generation in a reviewed
// storage schema before these bytes can be persisted or compared across jobs.
const EncodingID = "unit-int8-fixed127-v1"

// EncodeUnit normalizes a nonzero finite vector, scales each component by 127,
// and rounds ties away from zero to a signed byte in [-127,127]. The scale is
// global and fixed, not per vector. This loses magnitude and is suitable only
// for cosine ranking after empirical quality and security review.
func EncodeUnit(vector []float64) ([Dimensions]byte, error) {
	var out [Dimensions]byte
	if len(vector) != Dimensions {
		return out, fmt.Errorf("invalid vector dimension")
	}
	var norm float64
	for _, v := range vector {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return out, fmt.Errorf("non-finite vector")
		}
		norm = math.Hypot(norm, v)
	}
	if norm == 0 || math.IsInf(norm, 0) {
		return out, fmt.Errorf("invalid vector magnitude")
	}
	var nonzero bool
	for i, v := range vector {
		q := math.Round((v / norm) * 127)
		if q < -127 || q > 127 || math.IsNaN(q) {
			return [Dimensions]byte{}, fmt.Errorf("invalid quantized component")
		}
		signed := int8(q)
		out[i] = byte(signed)
		nonzero = nonzero || signed != 0
	}
	if !nonzero {
		return [Dimensions]byte{}, fmt.Errorf("zero quantized vector")
	}
	return out, nil
}

// Cosine rejects reserved -128 and all-zero representations. Its input must
// already be bound to the same model and encoding by the authorized caller.
func Cosine(a, b [Dimensions]byte) (float64, error) {
	var dot, aa, bb int64
	for i := range a {
		x, y := int64(int8(a[i])), int64(int8(b[i]))
		if x == -128 || y == -128 {
			return 0, fmt.Errorf("reserved component")
		}
		dot += x * y
		aa += x * x
		bb += y * y
	}
	if aa == 0 || bb == 0 {
		return 0, fmt.Errorf("zero vector")
	}
	return float64(dot) / math.Sqrt(float64(aa)*float64(bb)), nil
}
