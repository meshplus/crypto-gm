package sm2

import (
	"math/big"
	"sync"
)

type sm2FieldElement [9]uint32
type sm2LargeFieldElement [17]uint64

const (
	bottom28Bits = 0xFFFFFFF
	bottom29Bits = 0x1FFFFFFF
)

var (
	sm2RInverse, _  = new(big.Int).SetString("7ffffffd80000002fffffffe000000017ffffffe800000037ffffffc80000002", 16)
	precomputedOnce sync.Once
	sm2Precomputed  [43][32 * 18]uint32
	zero            = &sm2FieldElement{0, 0, 0, 0, 0, 0, 0, 0, 0}
)

func (curve sm2Curve) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	var X1, Y1, Z1, X2, Y2, Z2, X3, Y3, Z3 sm2FieldElement

	z1 := zForAffine(x1, y1)
	z2 := zForAffine(x2, y2)
	sm2FromBig(&X1, x1)
	sm2FromBig(&Y1, y1)
	sm2FromBig(&Z1, z1)
	sm2FromBig(&X2, x2)
	sm2FromBig(&Y2, y2)
	sm2FromBig(&Z2, z2)
	sm2PointAdd(&X1, &Y1, &Z1, &X2, &Y2, &Z2, &X3, &Y3, &Z3)
	return sm2ToAffine(&X3, &Y3, &Z3)
}

func (curve sm2Curve) Double(x1, y1 *big.Int) (*big.Int, *big.Int) {
	var X1, Y1, Z1 sm2FieldElement

	z1 := zForAffine(x1, y1)
	sm2FromBig(&X1, x1)
	sm2FromBig(&Y1, y1)
	sm2FromBig(&Z1, z1)
	sm2PointDouble(&X1, &Y1, &Z1, &X1, &Y1, &Z1)
	return sm2ToAffine(&X1, &Y1, &Z1)
}

func (curve sm2Curve) ScalarMult(x1, y1 *big.Int, k []byte) (*big.Int, *big.Int) {
	var scalarReversed [8]uint32
	var X, Y, Z, X1, Y1 sm2FieldElement

	sm2FromBig(&X1, x1)
	sm2FromBig(&Y1, y1)
	sm2GetScalar2(&scalarReversed, k)
	sm2ScalarMult2(&X, &Y, &Z, &X1, &Y1, &scalarReversed)
	return sm2ToAffine(&X, &Y, &Z)
}

func (curve sm2Curve) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
	var scalarReversed [8]uint32
	var X, Y, Z sm2FieldElement

	sm2GetScalar2(&scalarReversed, k)
	sm2BaseMult2(&X, &Y, &Z, &scalarReversed)
	return sm2ToAffine(&X, &Y, &Z)
}
