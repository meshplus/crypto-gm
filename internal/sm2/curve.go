package sm2

import (
	"crypto/elliptic"
	"math/big"
	"sync"
)

var bigIntPool = &sync.Pool{
	New: func() interface{} {
		return new([4]uint64)
	},
}

//GetInt get big.Int
func getInt() *[4]uint64 {
	return bigIntPool.Get().(*[4]uint64)
}

//PutInt put big.Int
func putInt(in *[4]uint64) {
	bigIntPool.Put(in)
}

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

//sm2_64bit is sm2 curve init function
func sm2_64bit() elliptic.Curve {
	return &sm2
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
var curveB = [4]uint64{0x90D230632BC0DD42, 0x71CF379AE9B537AB, 0x527981505EA51C3C, 0x240FE188BA20E2C8} //Mont
var curveP = [4]uint64{0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF00000000, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFEFFFFFFFF} //non Mont
func (curve sm2Curve) IsOnCurve(X, Y *big.Int) bool {
	//asm: 201ns go: 1617ns @macbook pro 13
	var x, y [4]uint64
	fromBig(&y, Y)
	fromBig(&x, X)
	return isOnCurve(&x, &y)

}

func isOnCurve(x, y *[4]uint64) bool {
	var x3, y2 [4]uint64
	// 0<X,Y<p
	if biggerThan(x, &curveP) || biggerThan(y, &curveP) {
		return false
	}
	// y² = x³ - 3x + b
	p256Mul(y, y, &RR)
	p256Mul(&y2, y, y) //y^2

	p256Mul(x, x, &RR)
	p256Mul(&x3, x, x)   //x^2
	p256Mul(&x3, &x3, x) //tmp = x^3

	p256Sub(&x3, &x3, x)
	p256Sub(&x3, &x3, x)
	p256Sub(&x3, &x3, x)

	p256Add(&x3, &x3, &curveB)
	return (x3[0]^y2[0])|(x3[1]^y2[1])|(x3[2]^y2[2])|(x3[3]^y2[3]) == 0
}

func zForAffine(z *[4]uint64, x, y *big.Int) {
	if x.Sign() != 0 || y.Sign() != 0 {
		*z = one
		return
	}
	*z = zero
}

func (curve sm2Curve) Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
	var res, in1, in2 sm2Point
	maybeReduceModP(&in1.xyz[0], x1)
	maybeReduceModP(&in1.xyz[1], y1)
	maybeReduceModP(&in2.xyz[0], x2)
	maybeReduceModP(&in2.xyz[1], y2)
	zForAffine(&in1.xyz[2], x1, y1)
	zForAffine(&in2.xyz[2], x2, y2)
	in1.toMont()
	in2.toMont()
	sm2PointAdd1Asm(&res.xyz, &in1.xyz, &in2.xyz)
	res.toAffine()
	fromMont(&res.xyz[0], &res.xyz[0])
	fromMont(&res.xyz[1], &res.xyz[1])
	return toBig(&res.xyz[0]), toBig(&res.xyz[1])
}

func (curve sm2Curve) Double(x1, y1 *big.Int) (*big.Int, *big.Int) {
	var res, in sm2Point
	maybeReduceModP(&in.xyz[0], x1)
	maybeReduceModP(&in.xyz[1], y1)
	zForAffine(&in.xyz[2], x1, y1)
	in.toMont()
	sm2PointDouble1Asm(&res.xyz, &in.xyz)
	res.toAffine()
	fromMont(&res.xyz[0], &res.xyz[0])
	fromMont(&res.xyz[1], &res.xyz[1])
	return toBig(&res.xyz[0]), toBig(&res.xyz[1])
}

func (curve sm2Curve) ScalarMult(x1, y1 *big.Int, k []byte) (*big.Int, *big.Int) {
	var (
		res    sm2Point
		scalar [4]uint64
	)
	fromBig(&res.xyz[0], x1)
	fromBig(&res.xyz[1], y1)
	zForAffine(&res.xyz[2], x1, y1)
	res.toMont()

	big2little(&scalar, k)
	getScalar(&scalar)

	res.sm2ScalarMult(scalar[:])
	res.toAffine()
	fromMont(&res.xyz[0], &res.xyz[0])
	fromMont(&res.xyz[1], &res.xyz[1])
	return toBig(&res.xyz[0]), toBig(&res.xyz[1])
}

func (curve sm2Curve) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
	var (
		res    sm2Point
		scalar [4]uint64
	)
	big2little(&scalar, k)
	getScalar(&scalar)
	res.sm2BaseMult(scalar[:])
	res.toAffine()
	fromMont(&res.xyz[0], &res.xyz[0])
	fromMont(&res.xyz[1], &res.xyz[1])
	return toBig(&res.xyz[0]), toBig(&res.xyz[1])
}

func (curve sm2Curve) combinedMult(X, Y *[4]uint64, baseScalar, scalar *[4]uint64) {
	var r1, r2 sm2Point
	getScalar(baseScalar)
	r1IsInfinity := scalarIsZero(baseScalar)
	r1.sm2BaseMult(baseScalar[:])

	getScalar(scalar)
	r2IsInfinity := scalarIsZero(scalar)
	maybeReduceModPASM(X)
	maybeReduceModPASM(Y)
	p256Mul(&r2.xyz[0], X, &RR)
	p256Mul(&r2.xyz[1], Y, &RR)

	// This sets r2's Z value to 1, in the Montgomery domain.
	r2.xyz[2] = R
	r2.sm2ScalarMult(scalar[:])

	var sum, double sm2Point
	pointsEqual := sm2PointAdd2Asm(&sum.xyz, &r1.xyz, &r2.xyz)
	sm2PointDouble1Asm(&double.xyz, &r1.xyz)
	sum.copyConditional(&double, pointsEqual)
	sum.copyConditional(&r1, r2IsInfinity)
	sum.copyConditional(&r2, r1IsInfinity)

	p256Invert(&sum.xyz[2], &sum.xyz[2])
	p256Sqr(&sum.xyz[2], &sum.xyz[2], 1)
	p256Mul(&sum.xyz[0], &sum.xyz[0], &sum.xyz[2])
	p256Mul(&sum.xyz[0], &sum.xyz[0], &one)
	*X = sum.xyz[0]
}

func (p *sm2Point) sm2BaseMult(scalar []uint64) {
	wvalue := (scalar[0] << 1) & 0x7f
	sel, sign := boothW6(uint(wvalue))
	p256SelectBase(&p.xyz, 0, sel)
	p256NegCond(&p.xyz[1], sign)

	// (This is one, in the Montgomery domain.)
	copy(p.xyz[2][:], R[:])

	var t sm2Point
	// (This is one, in the Montgomery domain.
	copy(t.xyz[2][:], R[:])

	index := uint(5)
	zeroInner := sel

	for i := 1; i < 43; i++ {
		if index < 192 {
			wvalue = ((scalar[index/64] >> (index % 64)) + (scalar[index/64+1] << (64 - (index % 64)))) & 0x7f
		} else {
			wvalue = (scalar[index/64] >> (index % 64)) & 0x7f
		}
		index += 6
		sel, sign = boothW6(uint(wvalue))
		p256SelectBase(&t.xyz, i, sel)
		p256PointAddAffineAsm(&p.xyz, &p.xyz, &t.xyz, sign, sel, zeroInner)
		zeroInner |= sel
	}

}

type sm2Point struct {
	xyz [3][4]uint64
}

func (p *sm2Point) p256StorePoint(r *[16 * 4 * 3]uint64, index int) {
	copy(r[index*12:index*12+4], p.xyz[0][:])
	copy(r[index*12+4:index*12+8], p.xyz[1][:])
	copy(r[index*12+8:index*12+12], p.xyz[2][:])

}

func (p *sm2Point) toMont() {
	p256Mul(&p.xyz[0], &p.xyz[0], &RR)
	p256Mul(&p.xyz[1], &p.xyz[1], &RR)
	p256Mul(&p.xyz[2], &p.xyz[2], &RR)

}

// CopyConditional copies overwrites p with src if v == 1, and leaves p
// unchanged if v == 0.
func (p *sm2Point) copyConditional(src *sm2Point, v int) {
	//pMask := uint64(v) - 1
	//srcMask := ^pMask
	//
	//for i := 0; i < 3; i++ {
	//	for j := 0; j < 4; j++ {
	//		p.xyz[i][j] = (p.xyz[i][j] & pMask) | (src.xyz[i][j] & srcMask)
	//	}
	//}
	//对于验签来说，并没有必要考虑时间信道攻击
	if v > 0 {
		for i := 0; i < 3; i++ {
			for j := 0; j < 4; j++ {
				p.xyz[i][j] = src.xyz[i][j]
			}
		}
	}
}

func (p *sm2Point) toAffine() {
	var zz, zInv [4]uint64
	p256Invert(&zInv, &p.xyz[2])
	zz[0], zz[1], zz[2], zz[3] = zInv[0], zInv[1], zInv[2], zInv[3]
	p256Sqr(&zz, &zz, 1)
	p256Mul(&p.xyz[0], &p.xyz[0], &zz)
	p256Mul(&zz, &zz, &zInv)
	p256Mul(&p.xyz[1], &p.xyz[1], &zz)
}

func (p *sm2Point) sm2ScalarMult(scalar []uint64) {
	// precomp is a table of precomputed points that stores powers of p
	// from p^1 to p^16.
	var precomp [16 * 4 * 3]uint64
	var t0, t1, t2, t3 sm2Point
	// Prepare the table
	p.p256StorePoint(&precomp, 0) // 1

	sm2PointDouble2Asm(&t0.xyz, &p.xyz)
	sm2PointDouble2Asm(&t1.xyz, &t0.xyz)
	sm2PointDouble2Asm(&t2.xyz, &t1.xyz)
	sm2PointDouble2Asm(&t3.xyz, &t2.xyz)
	t0.p256StorePoint(&precomp, 1)  // 2
	t1.p256StorePoint(&precomp, 3)  // 4
	t2.p256StorePoint(&precomp, 7)  // 8
	t3.p256StorePoint(&precomp, 15) // 16

	sm2PointAdd2Asm(&t0.xyz, &t0.xyz, &p.xyz)

	sm2PointAdd2Asm(&t1.xyz, &t1.xyz, &p.xyz)
	sm2PointAdd2Asm(&t2.xyz, &t2.xyz, &p.xyz)
	t0.p256StorePoint(&precomp, 2) // 3
	t1.p256StorePoint(&precomp, 4) // 5
	t2.p256StorePoint(&precomp, 8) // 9

	sm2PointDouble2Asm(&t0.xyz, &t0.xyz)
	sm2PointDouble2Asm(&t1.xyz, &t1.xyz)
	t0.p256StorePoint(&precomp, 5) // 6
	t1.p256StorePoint(&precomp, 9) // 10

	sm2PointAdd2Asm(&t2.xyz, &t0.xyz, &p.xyz)
	sm2PointAdd2Asm(&t1.xyz, &t1.xyz, &p.xyz)
	t2.p256StorePoint(&precomp, 6)  // 7
	t1.p256StorePoint(&precomp, 10) // 11

	sm2PointDouble2Asm(&t0.xyz, &t0.xyz)
	sm2PointDouble2Asm(&t2.xyz, &t2.xyz)
	t0.p256StorePoint(&precomp, 11) // 12
	t2.p256StorePoint(&precomp, 13) // 14

	sm2PointAdd2Asm(&t0.xyz, &t0.xyz, &p.xyz)
	sm2PointAdd2Asm(&t2.xyz, &t2.xyz, &p.xyz)
	t0.p256StorePoint(&precomp, 12) // 13
	t2.p256StorePoint(&precomp, 14) // 15

	// Start scanning the window from top bit
	index := uint(254)
	var sel, sign int

	wvalue := (scalar[index/64] >> (index % 64)) & 0x3f
	sel, _ = boothW5(uint(wvalue))

	p256Select(&p.xyz, &precomp, sel)
	zeroInner := sel

	for index > 4 {
		index -= 5
		sm2PointDouble2Asm(&p.xyz, &p.xyz)
		sm2PointDouble2Asm(&p.xyz, &p.xyz)
		sm2PointDouble2Asm(&p.xyz, &p.xyz)
		sm2PointDouble2Asm(&p.xyz, &p.xyz)
		sm2PointDouble2Asm(&p.xyz, &p.xyz)

		if index < 192 {
			wvalue = ((scalar[index/64] >> (index % 64)) + (scalar[index/64+1] << (64 - (index % 64)))) & 0x3f
		} else {
			wvalue = (scalar[index/64] >> (index % 64)) & 0x3f
		}

		sel, sign = boothW5(uint(wvalue))

		p256Select(&t0.xyz, &precomp, sel)
		p256NegCond(&t0.xyz[1], sign)
		sm2PointAdd2Asm(&t1.xyz, &t0.xyz, &p.xyz)
		p256MovCond(&t1.xyz, &t1.xyz, &p.xyz, sel)
		p256MovCond(&p.xyz, &t1.xyz, &t0.xyz, zeroInner)
		zeroInner |= sel
	}

	sm2PointDouble2Asm(&p.xyz, &p.xyz)
	sm2PointDouble2Asm(&p.xyz, &p.xyz)
	sm2PointDouble2Asm(&p.xyz, &p.xyz)
	sm2PointDouble2Asm(&p.xyz, &p.xyz)
	sm2PointDouble2Asm(&p.xyz, &p.xyz)

	wvalue = (scalar[0] << 1) & 0x3f
	sel, sign = boothW5(uint(wvalue))

	p256Select(&t0.xyz, &precomp, sel)
	p256NegCond(&t0.xyz[1], sign)
	sm2PointAdd2Asm(&t1.xyz, &p.xyz, &t0.xyz)
	p256MovCond(&t1.xyz, &t1.xyz, &p.xyz, sel)
	p256MovCond(&p.xyz, &t1.xyz, &t0.xyz, zeroInner)
}
