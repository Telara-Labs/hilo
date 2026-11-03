package embedding

import (
	"math"
	"testing"
)

func TestEncodeFixedScaleAndCosine(t *testing.T) {
	a, b := make([]float64, Dimensions), make([]float64, Dimensions)
	a[0], a[1] = 3, 4
	b[0], b[1] = 30, 40
	qa, err := EncodeUnit(a)
	if err != nil {
		t.Fatal(err)
	}
	qb, err := EncodeUnit(b)
	if err != nil {
		t.Fatal(err)
	}
	if qa != qb || int8(qa[0]) != 76 || int8(qa[1]) != 102 {
		t.Fatalf("unexpected fixed scale %d %d", int8(qa[0]), int8(qa[1]))
	}
	cosine, err := Cosine(qa, qb)
	if err != nil || math.Abs(cosine-1) > 1e-12 {
		t.Fatalf("cosine %v %v", cosine, err)
	}
	b[0], b[1] = -4, 3
	qb, _ = EncodeUnit(b)
	cosine, err = Cosine(qa, qb)
	if err != nil || math.Abs(cosine) > .01 {
		t.Fatalf("orthogonal distortion %v %v", cosine, err)
	}
}
func TestEncodeAndCompareRejectInvalid(t *testing.T) {
	if _, err := EncodeUnit(nil); err == nil {
		t.Fatal("accepted wrong dimensions")
	}
	v := make([]float64, Dimensions)
	if _, err := EncodeUnit(v); err == nil {
		t.Fatal("accepted zero vector")
	}
	v[0] = math.NaN()
	if _, err := EncodeUnit(v); err == nil {
		t.Fatal("accepted NaN")
	}
	v[0] = math.Inf(1)
	if _, err := EncodeUnit(v); err == nil {
		t.Fatal("accepted infinity")
	}
	var a, b [Dimensions]byte
	a[0] = 128
	b[0] = 1
	if _, err := Cosine(a, b); err == nil {
		t.Fatal("accepted reserved value")
	}
	a[0] = 0
	if _, err := Cosine(a, b); err == nil {
		t.Fatal("accepted zero encoding")
	}
}
