package internal

import (
	"crypto/elliptic"
	"math/big"
	"sync"
)

/*
SM2椭圆曲线公钥密码算法推荐曲线参数
推荐使用素数域256位椭圆曲线
椭圆曲线方程：y2 = x3 + ax + b。
曲线参数：
p=FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFF
a=FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFC
b=28E9FA9E 9D9F5E34 4D5A9E4B CF6509A7 F39789F5 15AB8F92 DDBCBD41 4D940E93
n=FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF 7203DF6B 21C6052B 53BBF409 39D54123
Gx=32C4AE2C 1F198119 5F990446 6A39C994 8FE30BBF F2660BE1 715A4589 334C74C7
Gy=BC3736A2 F4F6779C 59BDCEE3 6B692153 D0A9877C C62A4740 02DF32E5 2139F0A0
*/
type sm2Curve struct {
	elliptic.CurveParams
}

var sm2 sm2Curve

//nolint
//Sm2_32bit is sm2 curve init function
func Sm2_32bit() elliptic.Curve {
	return &sm2
}

var bigIntPool = &sync.Pool{
	New: func() interface{} {
		return new(big.Int)
	},
}

//GetInt get big.Int
func GetInt() *big.Int {
	return bigIntPool.Get().(*big.Int)
}

//PutInt put big.Int
func PutInt(in *big.Int) {
	bigIntPool.Put(in)
}

func init() {
	sm2.Name = "sm2"
	sm2.P, _ = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
	sm2.N, _ = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
	sm2.B, _ = new(big.Int).SetString("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16)
	sm2.Gx, _ = new(big.Int).SetString("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
	sm2.Gy, _ = new(big.Int).SetString("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16)
	sm2.BitSize = 256
}

func (curve sm2Curve) Params() *elliptic.CurveParams {
	return &curve.CurveParams
}

// y^2 = x^3 + ax + b
func (curve sm2Curve) IsOnCurve(X, Y *big.Int) bool {
	// 0<X,Y<p
	if X.Sign() < 0 || !(X.Cmp(curve.P) < 0) || Y.Sign() < 0 || !(Y.Cmp(curve.P) < 0) {
		return false
	}
	// y² = x³ - 3x + b
	y2 := GetInt().Mul(Y, Y)
	y2.Mod(y2, curve.P)

	x3 := GetInt().Mul(X, X)
	x3.Mul(x3, X)

	threeX := GetInt().Lsh(X, 1)
	threeX.Add(threeX, X)

	x3.Sub(x3, threeX)
	x3.Add(x3, curve.B)
	x3.Mod(x3, curve.P)

	ret := x3.Cmp(y2) == 0
	PutInt(y2)
	PutInt(x3)
	PutInt(threeX)
	return ret
}

func zForAffine(x, y *big.Int) *big.Int {
	if x.Sign() != 0 || y.Sign() != 0 {
		return oneBig
	}
	return zeroBig
}

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
