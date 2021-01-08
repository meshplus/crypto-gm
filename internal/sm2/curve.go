package sm2

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
	*elliptic.CurveParams
}

var (
	sm2      sm2Curve
	initOnce sync.Once
)

//Sm2 is sm2 curve init function
func Sm2() elliptic.Curve {
	initOnce.Do(initSm2)
	return sm2
}
func initSm2() {
	sm2.CurveParams = &elliptic.CurveParams{Name: "sm2"}
	sm2.P, _ = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
	sm2.N, _ = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
	sm2.B, _ = new(big.Int).SetString("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16)
	sm2.Gx, _ = new(big.Int).SetString("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
	sm2.Gy, _ = new(big.Int).SetString("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16)
	sm2.BitSize = 256
}

func (curve sm2Curve) Params() *elliptic.CurveParams {
	return curve.CurveParams
}

// y^2 = x^3 + ax + b
func (curve sm2Curve) IsOnCurve(X, Y *big.Int) bool {
	// 0<X,Y<p
	if X.Sign() < 0 || !(X.Cmp(curve.P) < 0) || Y.Sign() < 0 || !(Y.Cmp(curve.P) < 0) {
		return false
	}
	// y² = x³ - 3x + b
	y2 := new(big.Int).Mul(Y, Y)
	y2.Mod(y2, curve.P)

	x3 := new(big.Int).Mul(X, X)
	x3.Mul(x3, X)

	threeX := new(big.Int).Lsh(X, 1)
	threeX.Add(threeX, X)

	x3.Sub(x3, threeX)
	x3.Add(x3, curve.B)
	x3.Mod(x3, curve.P)

	return x3.Cmp(y2) == 0
}

func zForAffine(x, y *big.Int) *big.Int {
	z := new(big.Int)
	if x.Sign() != 0 || y.Sign() != 0 {
		return z.SetUint64(1)
	}
	return z
}
