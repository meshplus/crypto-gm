package sm2

import (
	"encoding/binary"
	"github.com/meshplus/crypto-gm/internal/sm2/internal"
	"math/big"
	"unsafe"
)

var (
	//RR =  R * R mod P
	RR = [4]uint64{0x0000000200000003, 0x00000002ffffffff, 0x0000000100000001, 0x400000002}
	//R =  R mod P
	R    = [4]uint64{0x0000000000000001, 0x00000000ffffffff, 0x0000000000000000, 0x100000000}
	one  = [4]uint64{1, 0, 0, 0}
	zero = [4]uint64{0, 0, 0, 0}
	//RRN = R * R mod N
	RRN = [4]uint64{0x901192af7c114f20, 0x3464504ade6fa2fa, 0x620fc84c3affe0d4, 0x1eb5e412a22b3d3b}
)

//Montgomery Multiplication, a and b should Montgomery format
func mRInv(in *[4]uint64, a uint64)

// fromBig converts a *big.Int into a format used by this code.
func fromBig(out *[4]uint64, big *big.Int) {
	out[0], out[1], out[2], out[3] = 0, 0, 0, 0
	src := big.Bits()
	if len(src) > 4 {
		src = src[:4]
	}
	for i, v := range src {
		out[i] = uint64(v)
	}
}

func toBig(in *[4]uint64) *big.Int {
	return new(big.Int).SetBits([]big.Word{big.Word(in[0]), big.Word(in[1]), big.Word(in[2]), big.Word(in[3])})

}
func fromMont(res, in *[4]uint64) {
	p256Mul(res, in, &one)
}

//REDC64 is a REDC function
//go:noescape
func REDC64(in *[4]uint64)

//go:noescape
func orderMul(res, a, b *[4]uint64)

//go:noescape
func orderSqr(res, in *[4]uint64, n int)

//go:noescape
func p256Mul(res, a, b *[4]uint64)

//go:noescape
func p256Sqr(res, a *[4]uint64, n int)

//go:noescape
func redc1111(a *[4]uint64)

//go:noescape
func redc2222(a *[4]uint64)

//go:noescape
func smallOrderMul(res, a *[4]uint64, b *uint64)

// test function for mulxq
//go:noescape
func mul(out *[2]uint64, a, b uint64)

func ordInverse(in *[4]uint64) {
	var all [48]uint64
	_1 := (*[4]uint64)(unsafe.Pointer(&all[0]))
	_10 := (*[4]uint64)(unsafe.Pointer(&all[4]))
	_11 := (*[4]uint64)(unsafe.Pointer(&all[8]))
	_101 := (*[4]uint64)(unsafe.Pointer(&all[12]))
	_111 := (*[4]uint64)(unsafe.Pointer(&all[16]))
	_1001 := (*[4]uint64)(unsafe.Pointer(&all[20]))
	x4 := (*[4]uint64)(unsafe.Pointer(&all[24]))
	x5 := (*[4]uint64)(unsafe.Pointer(&all[28]))
	x10 := (*[4]uint64)(unsafe.Pointer(&all[32]))
	x20 := (*[4]uint64)(unsafe.Pointer(&all[36]))
	x30 := (*[4]uint64)(unsafe.Pointer(&all[40]))
	x32 := (*[4]uint64)(unsafe.Pointer(&all[44]))

	orderMul(_1, in, &RRN)
	orderSqr(_10, _1, 1)

	orderMul(_11, _10, _1)

	orderMul(_101, _11, _10)

	orderMul(_111, _101, _10)

	orderMul(_1001, _111, _10)

	orderSqr(x4, _111, 1)
	orderMul(x4, x4, _1)

	orderSqr(x5, x4, 1)
	orderMul(x5, x5, _1)

	orderSqr(x10, x5, 5)
	orderMul(x10, x10, x5)

	orderSqr(x20, x10, 10)
	orderMul(x20, x20, x10)

	orderSqr(x30, x20, 10)
	orderMul(x30, x30, x10)

	orderSqr(in, x30, 1)
	orderMul(in, in, _1) //x31

	orderSqr(x32, in, 1)
	orderMul(x32, x32, _1)

	sqrs := []uint8{
		33, 32, 32, 4, 3,
		11, 6, 3, 4, 4,
		7, 5, 9, 5, 3,
		4, 5, 4, 6, 3,
		10, 5, 5, 4, 4,
		9, 5,
	}
	muls := []*[4]uint64{
		x32, x32, x32, _111, _1,
		x4, x5, _11, _101, _1001,
		_111, _11, _101, _101, _11,
		_101, _111, _111, x5, _101,
		_1001, _111, _111, _101, _101,
		_1001, _1,
	}

	for i, s := range sqrs {
		orderSqr(in, in, int(s))
		orderMul(in, in, muls[i])
	}
}

/*
sm2

1111111111111111111111111111111    x31
011111111111111111111111111111111  x32
11111111111111111111111111111111   x32
11111111111111111111111111111111
11111111111111111111111111111111
0000000000000000000000000000000011111111111111111111111111111111  x32
111111111111111111111111111111   x30
01 x1
*/
// mod P , out and in are in Montgomery form
func p256Invert(out, in *[4]uint64) {
	var all [40]uint64
	x1 := (*[4]uint64)(unsafe.Pointer(&all[0]))
	x2 := (*[4]uint64)(unsafe.Pointer(&all[4]))
	x4 := (*[4]uint64)(unsafe.Pointer(&all[8]))
	x6 := (*[4]uint64)(unsafe.Pointer(&all[12]))
	x7 := (*[4]uint64)(unsafe.Pointer(&all[16]))
	x8 := (*[4]uint64)(unsafe.Pointer(&all[20]))
	x15 := (*[4]uint64)(unsafe.Pointer(&all[24]))
	x30 := (*[4]uint64)(unsafe.Pointer(&all[28]))
	x31 := (*[4]uint64)(unsafe.Pointer(&all[32]))
	x32 := (*[4]uint64)(unsafe.Pointer(&all[36]))
	x1[0], x1[1], x1[2], x1[3] = in[0], in[1], in[2], in[3]
	p256Sqr(x2, in, 1)
	p256Mul(x2, x2, in)

	p256Sqr(x4, x2, 2)
	p256Mul(x4, x4, x2)

	p256Sqr(x6, x4, 2)
	p256Mul(x6, x6, x2)

	p256Sqr(x7, x6, 1)
	p256Mul(x7, x7, in)

	p256Sqr(x8, x7, 1)
	p256Mul(x8, x8, in)

	p256Sqr(x15, x8, 7)
	p256Mul(x15, x15, x7)

	p256Sqr(x30, x15, 15)
	p256Mul(x30, x30, x15)

	p256Sqr(x31, x30, 1)
	p256Mul(x31, x31, in) //x31

	p256Sqr(x32, x31, 1)
	p256Mul(x32, x32, in)

	p256Sqr(out, x31, 33)
	p256Mul(out, out, x32)

	p256Sqr(out, out, 32)
	p256Mul(out, out, x32)

	p256Sqr(out, out, 32)
	p256Mul(out, out, x32)

	p256Sqr(out, out, 32)
	p256Mul(out, out, x32)

	p256Sqr(out, out, 64)
	p256Mul(out, out, x32)

	p256Sqr(out, out, 30)
	p256Mul(out, out, x30)

	p256Sqr(out, out, 2)
	p256Mul(out, out, x1)

}

//go:noescape
func p256Sub(res, in1, in2 *[4]uint64)

//go:noescape
func p256Add(res, in1, in2 *[4]uint64)

//go:noescape
func orderAdd(out, a, b *[4]uint64)

//go:noescape
func orderSub(out, a, b *[4]uint64)

//go:noescape
func biggerThan(a, b *[4]uint64) bool

//go:noescape
func sm2PointAdd2Asm(res, in1, in2 *[3][4]uint64) int

//go:noescape
func sm2PointAdd1Asm(res, in1, in2 *[3][4]uint64)

/*
Assumptions: Z2=1.
Cost: 8M + 3S + 6add + 1*2.
Source: 2008 Giessmann.
Explicit formulas:
      T1 = Z1^2
      T2 = T1*Z1
      T1 = T1*X2
      T2 = T2*Y2
      T1 = X1-T1
      T2 = T2-Y1
      Z3 = Z1*T1
      T4 = T1^2
      T1 = T1*T4
      T4 = T4*X1
      X3 = T2^2
      X3 = X3+T1
      Y3 = T1*Y1
      T1 = 2*T4
      X3 = X3-T1
      T4 = X3-T4
      T4 = T4*T2
      Y3 = T4-Y3
*/
//当第二个操作数的z为1时，选用该函数，速度较快
func sm2PointAdd1(res, in1, in2 *[3][4]uint64, all *[12]uint64) {
	//var all [12]uint64
	t1 := (*[4]uint64)(unsafe.Pointer(&all[0]))
	t2 := (*[4]uint64)(unsafe.Pointer(&all[4]))
	t4 := (*[4]uint64)(unsafe.Pointer(&all[8]))

	p256Sqr(t1, &in1[2], 1)
	p256Mul(t2, t1, &in1[2])
	p256Mul(t1, t1, &in2[0])
	p256Mul(t2, t2, &in2[1])

	p256Sub(t1, &in1[0], t1)

	p256Sub(t2, t2, &in1[1])

	p256Mul(&res[2], &in1[2], t1)

	p256Sqr(t4, t1, 1)
	p256Mul(t1, t1, t4)
	p256Mul(t4, t4, &in1[0])

	p256Sqr(&res[0], t2, 1)
	p256Add(&res[0], &res[0], t1)

	p256Mul(&res[1], t1, &in1[1])

	p256Add(t1, t4, t4)

	p256Sub(&res[0], &res[0], t1)

	p256Sub(t4, &res[0], t4)

	p256Mul(t4, t4, t2)

	p256Sub(&res[1], t4, &res[1])

}

/*
Cost: 11M + 5S + 9add + 4*2.
Cost: 10M + 4S + 9add + 4*2 dependent upon the first point.
Source: 2007 Bernstein–Lange; note that the improvement from 12M+4S to 11M+5S was already mentioned in 2001 Bernstein http://cr.yp.to/talks.html#2001.10.29.
Explicit formulas:

u1 = x1.z2²
u2 = x2.z1²
s1 = y1.z2³
s2 = y2.z1³
h = u2 - u1
r = s2 - s1
x3 = r² - h³ - 2.u1.h²
Y3 = r. (u1.h² - x3) - s1.h³
z3 = z1.z2.h
*/
func sm2PointAdd2(res, in1, in2 *[3][4]uint64, all *[44]uint64) {
	//var all [44]uint64
	H3 := (*[4]uint64)(unsafe.Pointer(&all[0]))
	H2 := (*[4]uint64)(unsafe.Pointer(&all[4]))
	H := (*[4]uint64)(unsafe.Pointer(&all[8]))
	z11 := (*[4]uint64)(unsafe.Pointer(&all[12]))
	z22 := (*[4]uint64)(unsafe.Pointer(&all[16]))
	u1 := (*[4]uint64)(unsafe.Pointer(&all[20]))
	u2 := (*[4]uint64)(unsafe.Pointer(&all[24]))
	s1 := (*[4]uint64)(unsafe.Pointer(&all[28]))
	s2 := (*[4]uint64)(unsafe.Pointer(&all[32]))
	r := (*[4]uint64)(unsafe.Pointer(&all[36]))
	r2 := (*[4]uint64)(unsafe.Pointer(&all[40]))

	p256Sqr(z11, &in1[2], 1)
	p256Sqr(z22, &in2[2], 1)
	p256Mul(u1, &in1[0], z22)
	p256Mul(u2, &in2[0], z11)
	p256Mul(s1, &in1[1], &in2[2])
	p256Mul(s1, s1, z22)
	p256Mul(s2, &in2[1], &in1[2])
	p256Mul(s2, s2, z11)
	p256Sub(H, u2, u1)

	p256Sub(r, s2, s1)
	p256Sqr(r2, r, 1)
	p256Sqr(H2, H, 1)
	p256Mul(H3, H2, H)
	p256Mul(u1, u1, H2)

	p256Sub(&res[0], r2, H3)
	p256Sub(&res[0], &res[0], u1)
	p256Sub(&res[0], &res[0], u1)

	p256Sub(u1, u1, &res[0])
	p256Mul(&res[1], r, u1)
	p256Mul(s1, s1, H3)
	p256Sub(&res[1], &res[1], s1)

	p256Mul(&res[2], &in1[2], &in2[2])
	p256Mul(&res[2], &res[2], H)

}

/*
Assumptions: Z1=1.
Cost: 1M + 5S + 7add + 3*2 + 1*3 + 1*8.
Source: 2007 Bernstein–Lange.
Explicit formulas:
      XX = X1^2
      YY = Y1^2
      S = 2*((X1+YY)^2-XX-YYYY) = 4 *X1*YY
      M = 3*XX+a
      x3 = M^2-2*S
      YY = YY^2
      Y3 = M*(S-x3)-8*YYYY
      Z3 = 2*Y1
*/
// a = 3 * RR mod P
var a = [4]uint64{0x3, 0x2fffffffd, 0, 0x300000000}

func sm2PointDouble1(res, in *[3][4]uint64, all *[16]uint64) {
	xx := (*[4]uint64)(unsafe.Pointer(&all[0]))
	yy := (*[4]uint64)(unsafe.Pointer(&all[4]))
	s := (*[4]uint64)(unsafe.Pointer(&all[8]))
	m := (*[4]uint64)(unsafe.Pointer(&all[12]))

	p256Sqr(xx, &in[0], 1)
	p256Sqr(yy, &in[1], 1)
	p256Mul(s, &in[0], yy)
	p256Add(s, s, s)
	p256Add(s, s, s)

	p256Add(m, xx, xx)
	p256Add(m, m, xx)
	p256Sub(m, m, &a)

	p256Sqr(&res[0], m, 1)
	p256Sub(&res[0], &res[0], s)
	p256Sub(&res[0], &res[0], s)

	p256Sqr(yy, yy, 1)
	p256Sub(s, s, &res[0])
	p256Mul(&res[1], m, s)

	p256Add(yy, yy, yy)
	p256Add(yy, yy, yy)
	p256Add(yy, yy, yy)

	p256Sub(&res[1], &res[1], yy)
	p256Add(&res[2], &in[1], &in[1])
}

/*
Cost: 3M + 5S + 8add + 1*3 + 1*4 + 2*8.
Source: 2001 Bernstein "A software implementation of NIST P-224".
Explicit formulas:
      delta = Z1^2
      gamma = Y1^2
      beta = X1*gamma
      alpha = 3*(X1-delta)*(X1+delta) = 3(X1^2 - delta^2)
      X3 = alpha^2-8*beta
      Z3 = (Y1+Z1)^2-gamma-delta
      Y3 = alpha*(4*beta-X3)-8*gamma^2
*/
func sm2PointDouble2(res, in *[3][4]uint64, all *[24]uint64) {
	//var all [24]uint64
	delta := (*[4]uint64)(unsafe.Pointer(&all[0]))
	gamma := (*[4]uint64)(unsafe.Pointer(&all[4]))
	beta := (*[4]uint64)(unsafe.Pointer(&all[8]))
	alpha := (*[4]uint64)(unsafe.Pointer(&all[12]))
	t1 := (*[4]uint64)(unsafe.Pointer(&all[16]))
	t2 := (*[4]uint64)(unsafe.Pointer(&all[20]))

	p256Sqr(delta, &in[2], 1)
	p256Sqr(gamma, &in[1], 1)
	p256Mul(beta, &in[0], gamma)

	p256Sqr(t1, &in[0], 1)
	p256Sqr(t2, delta, 1)
	p256Sub(t1, t1, t2)
	p256Add(alpha, t1, t1)
	p256Add(alpha, alpha, t1)

	p256Sqr(&res[0], alpha, 1)
	p256Add(t2, beta, beta)
	p256Add(t2, t2, t2)
	p256Add(t2, t2, t2)
	p256Sub(&res[0], &res[0], t2)

	p256Mul(&res[2], &in[1], &in[2])
	p256Add(&res[2], &res[2], &res[2])

	p256Add(beta, beta, beta)
	p256Add(beta, beta, beta)
	p256Sub(beta, beta, &res[0])

	p256Sqr(gamma, gamma, 1)
	p256Mul(&res[1], alpha, beta)
	p256Add(t2, gamma, gamma)
	p256Add(t2, t2, t2)
	p256Add(t2, t2, t2)
	p256Sub(&res[1], &res[1], t2)

}

//go:noescape
func sm2PointDouble2Asm(res, in *[3][4]uint64)

//go:noescape
func sm2PointDouble1Asm(res, in *[3][4]uint64)

//InitTable is used to compute the p256Precomputed table
func InitTable() *[43][32 * 8]uint64 {
	p256Precomputed2 := new([43][32 * 8]uint64)
	// gx *R, gy *R
	basePoint := [3][4]uint64{
		{0x61328990f418029e, 0x3e7981eddca6c050, 0xd6a1ed99ac24c3c3, 0x91167a5ee1c13b05},
		{0xc1354e593c2d0ddd, 0xc1f5e5788d3295fa, 0x8d4cfb066e2a48f8, 0x63cd65d481d735bd},
		{0x0000000000000001, 0x00000000ffffffff, 0x0000000000000000, 0x100000000},
	}
	t1 := new([3][4]uint64)

	t2 := new([3][4]uint64)
	copy(t2[:], basePoint[:])
	zInv := new([4]uint64)
	zInvSq := new([4]uint64)
	for j := 0; j < 32; j++ {
		copy(t1[:], t2[:])
		for i := 0; i < 43; i++ {
			// The window size is 6 so we need to double 6 times.
			if i != 0 {
				for k := 0; k < 6; k++ {
					sm2PointDouble2Asm(t1, t1)
				}
			}
			// Convert the point to affine form. (Its values are
			// still in Montgomery form however.)
			p256Invert(zInv, &t1[2])
			p256Sqr(zInvSq, zInv, 1)
			p256Mul(zInv, zInv, zInvSq)

			p256Mul(&t1[0], &t1[0], zInvSq)
			p256Mul(&t1[1], &t1[1], zInv)

			copy(t1[2][:], basePoint[2][:])
			// Update the table entry
			copy(p256Precomputed2[i][j*8:j*8+4], t1[0][:])
			copy(p256Precomputed2[i][j*8+4:j*8+8], t1[1][:])
		}
		if j == 0 {
			sm2PointDouble2Asm(t2, &basePoint)
		} else {
			sm2PointAdd2Asm(t2, t2, &basePoint)
		}
	}
	return p256Precomputed2
}
func boothW5(in uint) (int, int) {
	var s = ^((in >> 5) - 1)
	var d = (1 << 6) - in - 1
	d = (d & s) | (in & (^s))
	d = (d >> 1) + (d & 1)
	return int(d), int(s & 1)
}

func boothW6(in uint) (int, int) {
	var s = ^((in >> 6) - 1)
	var d = (1 << 7) - in - 1
	d = (d & s) | (in & (^s))
	d = (d >> 1) + (d & 1)
	return int(d), int(s & 1)
}

//go:noescape
func p256SelectBase(point *[3][4]uint64, index, idx int)

// iff cond == 1  val <- -val
//go:noescape
func p256NegCond(val *[4]uint64, cond int)

// Point add with in2 being affine point, 对应z2=1 的情况
// If sign == 1 -> in2 = -in2
// If sel == 0 -> res = in1
// if zero == 0 -> res = in2

func p256PointAddAffineAsm(res, in1, in2 *[3][4]uint64, sign, sel, zero int) {
	if sign == 1 {
		p256NegCond(&in2[1], sign)
	}

	if sel == 0 {
		copy(res[:], in1[:])
		return
	}

	if zero == 0 {
		copy(res[:], in2[:])
		return
	}

	sm2PointAdd1Asm(res, in1, in2)
	return
}

// Constant time table access
//go:noescape
func p256Select(point *[3][4]uint64, table *[16 * 4 * 3]uint64, idx int)

// if cond == 0 res <- b; else res <- a
//go:noescape
func p256MovCond(res, a, b *[3][4]uint64, cond int)

// getScalar endian-swaps the big-endian scalar value from in and writes it
// to out. If the scalar is equal or greater than the order of the group, it's
// reduced modulo that order.
func getScalar(in *[4]uint64) {
	if biggerThan(in, n) {
		orderAdd(in, in, &zero)
	}
}

// scalarIsZero returns 1 if scalar represents the zero value, and zero
// otherwise.
func scalarIsZero(scalar *[4]uint64) int {
	return uint64IsZero(scalar[0] | scalar[1] | scalar[2] | scalar[3])
}

// uint64IsZero returns 1 if x is zero and zero otherwise.
func uint64IsZero(x uint64) int {
	x = ^x
	x &= x >> 32
	x &= x >> 16
	x &= x >> 8
	x &= x >> 4
	x &= x >> 2
	x &= x >> 1
	return int(x & 1)
}

func maybeReduceModP(dist *[4]uint64, src *big.Int) {
	srcBits := src.Bits()
	if len(srcBits) > 4 {
		tmp := internal.GetInt()
		srcBits = tmp.Mod(src, sm2.P).Bits()
		internal.PutInt(tmp)
	}

	dist[0], dist[1], dist[2], dist[3] = 0, 0, 0, 0
	for i := range srcBits {
		dist[i] = uint64(srcBits[i])
	}
	maybeReduceModPASM(dist)
}

func maybeReduceModPASM(inout *[4]uint64)

func big2little(out *[4]uint64, in []byte) {
	var tmp [32]byte
	if len(in) < 32 {
		copy(tmp[32-len(in):], in)
		out[3] = binary.BigEndian.Uint64(tmp[0:8])
		out[2] = binary.BigEndian.Uint64(tmp[8:16])
		out[1] = binary.BigEndian.Uint64(tmp[16:24])
		out[0] = binary.BigEndian.Uint64(tmp[24:32])
	} else {
		out[3] = binary.BigEndian.Uint64(in[0:8])
		out[2] = binary.BigEndian.Uint64(in[8:16])
		out[1] = binary.BigEndian.Uint64(in[16:24])
		out[0] = binary.BigEndian.Uint64(in[24:32])
	}
}

func little2big(out []byte, in *[4]uint64) {
	binary.BigEndian.PutUint64(out[24:32], in[0])
	binary.BigEndian.PutUint64(out[16:24], in[1])
	binary.BigEndian.PutUint64(out[8:16], in[2])
	binary.BigEndian.PutUint64(out[0:8], in[3])
}
