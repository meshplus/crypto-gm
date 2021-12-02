package internal

import (
	"bytes"
	"math/big"
)

/*
base point
&[830053d 328990f 6c04fe1 c0f72e5 1e19f3c 666b093 175a87b ec38276 222cf4b]
&[185a1bba 354e593 1295fac1 f2bc469 47c60fa c19b8a9 f63533e 903ae6b c79acba]
&[2 0 1fffff00 7ff 0 0 0 2000000 0]
*/
func InitTable() {
	// gx *R, gy *R
	basePoint := [3]sm2FieldElement{
		{0x830053d, 0x328990f, 0x6c04fe1, 0xc0f72e5, 0x1e19f3c, 0x666b093, 0x175a87b, 0xec38276, 0x222cf4b},
		{0x185a1bba, 0x354e593, 0x1295fac1, 0xf2bc469, 0x47c60fa, 0xc19b8a9, 0xf63533e, 0x903ae6b, 0xc79acba},
		{0x2, 0, 0x1fffff00, 0x7ff, 0, 0, 0, 0x2000000, 0x0},
	}
	t1 := new([3]sm2FieldElement)

	t2 := new([3]sm2FieldElement)
	copy(t2[:], basePoint[:])
	zInv := new(sm2FieldElement)
	zInvSq := new(sm2FieldElement)
	for j := 0; j < 32; j++ {
		copy(t1[:], t2[:])
		for i := 0; i < 43; i++ {
			// The window size is 6 so we need to double 6 times.
			if i != 0 {
				for k := 0; k < 6; k++ {
					sm2PointDouble(&t1[0], &t1[1], &t1[2], &t1[0], &t1[1], &t1[2])
				}
			}
			// Convert the point to affine form. (Its values are
			// still in Montgomery form however.)
			sm2InversP(zInv, &t1[2])
			sm2SquareTimes(zInvSq, zInv, 1)
			sm2Mul(zInv, zInv, zInvSq)

			sm2Mul(&t1[0], &t1[0], zInvSq)
			sm2Mul(&t1[1], &t1[1], zInv)

			copy(t1[2][:], basePoint[2][:])
			// Update the table entry
			copy(sm2Precomputed[i][j*18:j*18+9], t1[0][:])
			copy(sm2Precomputed[i][j*18+9:j*18+18], t1[1][:])
		}
		if j == 0 {
			sm2PointDouble(&t2[0], &t2[1], &t2[2], &basePoint[0], &basePoint[1], &basePoint[2])
		} else {
			sm2PointAdd(&basePoint[0], &basePoint[1], &basePoint[2], &t2[0], &t2[1], &t2[2], &t2[0], &t2[1], &t2[2])
		}
	}
}

func sm2GetScalar2(b *[8]uint32, a []byte) {
	x := new(big.Int).SetBytes(a)
	x.Mod(x, sm2.N)
	for i := 0; i < 8; i++ {
		if bits := x.Bits(); len(bits) > 0 {
			b[i] = uint32(bits[0])
		} else {
			b[i] = 0
		}
		x.Rsh(x, 32)
	}
}

// z2 = 1
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

func sm2PointAddMixed2(xOut, yOut, zOut, x1, y1, z1, x2, y2 *sm2FieldElement) {
	var t1, t2, t4 sm2FieldElement
	sm2Square(&t1, z1)
	sm2Mul(&t2, &t1, z1)
	sm2Mul(&t1, &t1, x2)
	sm2Mul(&t2, &t2, y2)
	sm2Sub(&t1, x1, &t1)
	sm2Sub(&t2, &t2, y1)
	sm2Mul(zOut, z1, &t1)
	sm2Square(&t4, &t1)
	sm2Mul(&t1, &t1, &t4)
	sm2Mul(&t4, &t4, x1)
	sm2Square(xOut, &t2)
	sm2Add(xOut, xOut, &t1)
	sm2Mul(yOut, &t1, y1)
	sm2Add(&t1, &t4, &t4)
	sm2Sub(xOut, xOut, &t1)
	sm2Sub(&t4, xOut, &t4)
	sm2Mul(&t4, &t4, &t2)
	sm2Sub(yOut, &t4, yOut)
}

func boothW6(in uint) (int, int) {
	var s = ^((in >> 6) - 1)
	var d = (1 << 7) - in - 1 // ^in & 0x7f
	d = (d & s) | (in & (^s)) // 正数：in，负数：in的反码
	d = (d >> 1) + (d & 1)    //
	return int(d), int(s & 1)
}
func negCond(p *sm2FieldElement, sign int) {
	if sign == 1 {
		sm2Sub(p, zero, p)
	}
}
func sm2BaseMult2(xOut, yOut, zOut *sm2FieldElement, scalar *[8]uint32) {
	precomputedOnce.Do(InitTable)
	wvalue := (scalar[0] << 1) & 0x7f
	sel, sign := boothW6(uint(wvalue))
	p256SelectBase2(xOut, yOut, 0, sel)

	negCond(yOut, sign)
	// (This is one, in the Montgomery domain.)
	*zOut = sm2FieldElement{0x2, 0, 0x1fffff00, 0x7ff, 0, 0, 0, 0x2000000, 0x0}
	t := new([3]sm2FieldElement)
	// (This is one, in the Montgomery domain.
	copy(t[2][:], (*zOut)[:])

	index := uint(5)
	zero := sel

	for i := 1; i < 43; i++ {
		if index < 224 {
			wvalue = ((scalar[index/32] >> (index % 32)) + (scalar[index/32+1] << (32 - (index % 32)))) & 0x7f
		} else {
			wvalue = (scalar[index/32] >> (index % 32)) & 0x7f
		}
		index += 6
		sel, sign = boothW6(uint(wvalue))
		p256SelectBase2(&t[0], &t[1], i, sel)
		sm2PointAddCond(xOut, yOut, zOut, xOut, yOut, zOut, &t[0], &t[1], sign, sel, zero)
		zero |= sel
	}
}
func sm2PointAddCond(xOut, yOut, zOut, x1, y1, z1, x2, y2 *sm2FieldElement, sign, sel, zero int) {
	if sign == 1 {
		negCond(y2, sign)
	}
	if sel == 0 {
		*xOut = *x1
		*yOut = *y1
		*zOut = *z1
		return
	}

	if zero == 0 {
		*xOut = *x2
		*yOut = *y2
		*zOut = sm2FieldElement{0x2, 0, 0x1fffff00, 0x7ff, 0, 0, 0, 0x2000000, 0x0}
		return
	}
	sm2PointAddMixed2(xOut, yOut, zOut, x1, y1, z1, x2, y2)
}
func p256SelectBase2(x, y *sm2FieldElement, index, idx int) {
	if idx == 0 {
		*x = sm2FieldElement{0, 0, 0, 0}
		*y = sm2FieldElement{0, 0, 0, 0}
		return
	}
	copy((*x)[:], sm2Precomputed[index][(idx-1)*18:(idx-1)*18+9])
	copy((*y)[:], sm2Precomputed[index][(idx-1)*18+9:(idx-1)*18+18])
}

func sm2PointToAffine(xOut, yOut, x, y, z *sm2FieldElement) {
	var zInv, zInvSq sm2FieldElement

	zz := sm2ToBig(z)
	zz.ModInverse(zz, sm2.P)
	sm2FromBig(&zInv, zz)
	//sm2InversP(&zInv, z)

	sm2Square(&zInvSq, &zInv)
	sm2Mul(xOut, x, &zInvSq)
	sm2Mul(&zInv, &zInv, &zInvSq)
	sm2Mul(yOut, y, &zInv)
}

func sm2ToAffine(x, y, z *sm2FieldElement) (xOut, yOut *big.Int) {
	var xx, yy sm2FieldElement

	sm2PointToAffine(&xx, &yy, x, y, z)
	return sm2ToBig(&xx), sm2ToBig(&yy)
}

func sm2FromAffine(xIn, yIn *big.Int) (x1, y1, z1 sm2FieldElement) {
	x, y, z := sm2FieldElement{}, sm2FieldElement{}, sm2FieldElement{}
	zIn := zForAffine(xIn, yIn)
	sm2FromBig(&x, xIn)
	sm2FromBig(&y, yIn)
	sm2FromBig(&z, zIn)
	return x, y, z
}

// (x3, y3, z3) = (x1, y1, z1) + (x2, y2, z2)
func sm2PointAdd(x1, y1, z1, x2, y2, z2, x3, y3, z3 *sm2FieldElement) {
	var u1, u2, z22, z12, s1, s2, h, h2, h3, r, r2 sm2FieldElement
	sm2Square(&z12, z1)   // z12 = z1 ^ 2
	sm2Square(&z22, z2)   // z22 = z2 ^ 2
	sm2Mul(&u1, x1, &z22) // u1 = x1 * z2 ^ 2
	sm2Mul(&u2, x2, &z12) // u2 = x2 * z1 ^ 2

	sm2Mul(&s1, y1, z2)
	sm2Mul(&s1, &s1, &z22) // s1 = y1 * z2 ^ 3
	sm2Mul(&s2, y2, z1)    // s2 = y2 * z1 ^ 3
	sm2Mul(&s2, &s2, &z12)

	sm2Sub(&h, &u2, &u1) // h = u2 - u1
	sm2Sub(&r, &s2, &s1) // r = s2 - s1

	sm2Square(&r2, &r)   // r2 = r ^ 2
	sm2Square(&h2, &h)   // h2 = h ^ 2
	sm2Mul(&h3, &h2, &h) // tm = h ^ 3
	sm2Mul(&u1, &u1, &h2)

	sm2Sub(x3, &r2, &h3)
	sm2Sub(x3, x3, &u1) // x3 = r ^ 2 - h ^ 3 - u1 * h ^ 2
	sm2Sub(x3, x3, &u1) // x3 = r ^ 2 - h ^ 3 - 2 * u1 * h ^ 2

	sm2Sub(&u1, &u1, x3) // tm = u1 * h ^ 2 - x3
	sm2Mul(y3, &r, &u1)
	sm2Mul(&s1, &s1, &h3) // tm = h ^ 3
	sm2Sub(y3, y3, &s1)   // y3 = r * (u1 * h ^ 2 - x3) - s1 * h ^ 3

	sm2Mul(z3, z1, z2)
	sm2Mul(z3, z3, &h) // z3 = z1 * z3 * h
}

// (x3, y3, z3) = 2(x, y, z)
func sm2PointDouble(x3, y3, z3, x, y, z *sm2FieldElement) {
	var delta, gamma, beta, alpha sm2FieldElement
	var t1, t2 sm2FieldElement
	sm2Square(&delta, z)
	sm2Square(&gamma, y)
	sm2Mul(&beta, x, &gamma)

	sm2Square(&t1, x)
	sm2Square(&t2, &delta)
	sm2Sub(&t1, &t1, &t2)
	sm2Add(&alpha, &t1, &t1)
	sm2Add(&alpha, &alpha, &t1)

	sm2Square(x3, &alpha)
	sm2Add(&t2, &beta, &beta)
	sm2Add(&t2, &t2, &t2)
	sm2Add(&t2, &t2, &t2)
	sm2Sub(x3, x3, &t2)

	sm2Mul(z3, y, z)
	sm2Add(z3, z3, z3)

	sm2Add(&beta, &beta, &beta)
	sm2Add(&beta, &beta, &beta)
	sm2Sub(&beta, &beta, x3)

	sm2Square(&gamma, &gamma)
	sm2Mul(y3, &alpha, &beta)
	sm2Add(&t2, &gamma, &gamma)
	sm2Add(&t2, &t2, &t2)
	sm2Add(&t2, &t2, &t2)
	sm2Sub(y3, y3, &t2)
}

// p256Zero31 is 0 mod p.
var sm2Zero31 = sm2FieldElement{0x7FFFFFF8, 0x3FFFFFFC, 0x800003FC, 0x3FFFDFFC, 0x7FFFFFFC, 0x3FFFFFFC, 0x7FFFFFFC, 0x37FFFFFC, 0x7FFFFFFC}

// c = a + b
func sm2Add(c, a, b *sm2FieldElement) {
	carry := uint32(0)
	for i := 0; ; i++ {
		c[i] = a[i] + b[i]
		c[i] += carry
		carry = c[i] >> 29
		c[i] &= bottom29Bits
		i++
		if i == 9 {
			break
		}
		c[i] = a[i] + b[i]
		c[i] += carry
		carry = c[i] >> 28
		c[i] &= bottom28Bits
	}
	sm2ReduceCarry(c, carry)
}

// c = a - b
func sm2Sub(c, a, b *sm2FieldElement) {
	var carry uint32

	for i := 0; ; i++ {
		c[i] = a[i] - b[i]
		c[i] += sm2Zero31[i]
		c[i] += carry
		carry = c[i] >> 29
		c[i] &= bottom29Bits
		i++
		if i == 9 {
			break
		}
		c[i] = a[i] - b[i]
		c[i] += sm2Zero31[i]
		c[i] += carry
		carry = c[i] >> 28
		c[i] &= bottom28Bits
	}
	sm2ReduceCarry(c, carry)
}

// c = a * b
func sm2Mul(c, a, b *sm2FieldElement) {
	var tmp sm2LargeFieldElement

	tmp[0] = uint64(a[0]) * uint64(b[0])
	tmp[1] = uint64(a[0])*(uint64(b[1])<<0) +
		uint64(a[1])*(uint64(b[0])<<0)
	tmp[2] = uint64(a[0])*(uint64(b[2])<<0) +
		uint64(a[1])*(uint64(b[1])<<1) +
		uint64(a[2])*(uint64(b[0])<<0)
	tmp[3] = uint64(a[0])*(uint64(b[3])<<0) +
		uint64(a[1])*(uint64(b[2])<<0) +
		uint64(a[2])*(uint64(b[1])<<0) +
		uint64(a[3])*(uint64(b[0])<<0)
	tmp[4] = uint64(a[0])*(uint64(b[4])<<0) +
		uint64(a[1])*(uint64(b[3])<<1) +
		uint64(a[2])*(uint64(b[2])<<0) +
		uint64(a[3])*(uint64(b[1])<<1) +
		uint64(a[4])*(uint64(b[0])<<0)
	tmp[5] = uint64(a[0])*(uint64(b[5])<<0) +
		uint64(a[1])*(uint64(b[4])<<0) +
		uint64(a[2])*(uint64(b[3])<<0) +
		uint64(a[3])*(uint64(b[2])<<0) +
		uint64(a[4])*(uint64(b[1])<<0) +
		uint64(a[5])*(uint64(b[0])<<0)
	tmp[6] = uint64(a[0])*(uint64(b[6])<<0) +
		uint64(a[1])*(uint64(b[5])<<1) +
		uint64(a[2])*(uint64(b[4])<<0) +
		uint64(a[3])*(uint64(b[3])<<1) +
		uint64(a[4])*(uint64(b[2])<<0) +
		uint64(a[5])*(uint64(b[1])<<1) +
		uint64(a[6])*(uint64(b[0])<<0)
	tmp[7] = uint64(a[0])*(uint64(b[7])<<0) +
		uint64(a[1])*(uint64(b[6])<<0) +
		uint64(a[2])*(uint64(b[5])<<0) +
		uint64(a[3])*(uint64(b[4])<<0) +
		uint64(a[4])*(uint64(b[3])<<0) +
		uint64(a[5])*(uint64(b[2])<<0) +
		uint64(a[6])*(uint64(b[1])<<0) +
		uint64(a[7])*(uint64(b[0])<<0)
	// tmp[8] has the greatest value but doesn't overflow. See logic in
	// p256Square.
	tmp[8] = uint64(a[0])*(uint64(b[8])<<0) +
		uint64(a[1])*(uint64(b[7])<<1) +
		uint64(a[2])*(uint64(b[6])<<0) +
		uint64(a[3])*(uint64(b[5])<<1) +
		uint64(a[4])*(uint64(b[4])<<0) +
		uint64(a[5])*(uint64(b[3])<<1) +
		uint64(a[6])*(uint64(b[2])<<0) +
		uint64(a[7])*(uint64(b[1])<<1) +
		uint64(a[8])*(uint64(b[0])<<0)
	tmp[9] = uint64(a[1])*(uint64(b[8])<<0) +
		uint64(a[2])*(uint64(b[7])<<0) +
		uint64(a[3])*(uint64(b[6])<<0) +
		uint64(a[4])*(uint64(b[5])<<0) +
		uint64(a[5])*(uint64(b[4])<<0) +
		uint64(a[6])*(uint64(b[3])<<0) +
		uint64(a[7])*(uint64(b[2])<<0) +
		uint64(a[8])*(uint64(b[1])<<0)
	tmp[10] = uint64(a[2])*(uint64(b[8])<<0) +
		uint64(a[3])*(uint64(b[7])<<1) +
		uint64(a[4])*(uint64(b[6])<<0) +
		uint64(a[5])*(uint64(b[5])<<1) +
		uint64(a[6])*(uint64(b[4])<<0) +
		uint64(a[7])*(uint64(b[3])<<1) +
		uint64(a[8])*(uint64(b[2])<<0)
	tmp[11] = uint64(a[3])*(uint64(b[8])<<0) +
		uint64(a[4])*(uint64(b[7])<<0) +
		uint64(a[5])*(uint64(b[6])<<0) +
		uint64(a[6])*(uint64(b[5])<<0) +
		uint64(a[7])*(uint64(b[4])<<0) +
		uint64(a[8])*(uint64(b[3])<<0)
	tmp[12] = uint64(a[4])*(uint64(b[8])<<0) +
		uint64(a[5])*(uint64(b[7])<<1) +
		uint64(a[6])*(uint64(b[6])<<0) +
		uint64(a[7])*(uint64(b[5])<<1) +
		uint64(a[8])*(uint64(b[4])<<0)
	tmp[13] = uint64(a[5])*(uint64(b[8])<<0) +
		uint64(a[6])*(uint64(b[7])<<0) +
		uint64(a[7])*(uint64(b[6])<<0) +
		uint64(a[8])*(uint64(b[5])<<0)
	tmp[14] = uint64(a[6])*(uint64(b[8])<<0) +
		uint64(a[7])*(uint64(b[7])<<1) +
		uint64(a[8])*(uint64(b[6])<<0)
	tmp[15] = uint64(a[7])*(uint64(b[8])<<0) +
		uint64(a[8])*(uint64(b[7])<<0)
	tmp[16] = uint64(a[8]) * (uint64(b[8]) << 0)
	sm2ReduceDegree(c, &tmp)
}

// b = a * a
func sm2Square(b, a *sm2FieldElement) {
	var tmp sm2LargeFieldElement

	tmp[0] = uint64(a[0]) * uint64(a[0])
	tmp[1] = uint64(a[0]) * (uint64(a[1]) << 1)
	tmp[2] = uint64(a[0])*(uint64(a[2])<<1) +
		uint64(a[1])*(uint64(a[1])<<1)
	tmp[3] = uint64(a[0])*(uint64(a[3])<<1) +
		uint64(a[1])*(uint64(a[2])<<1)
	tmp[4] = uint64(a[0])*(uint64(a[4])<<1) +
		uint64(a[1])*(uint64(a[3])<<2) +
		uint64(a[2])*uint64(a[2])
	tmp[5] = uint64(a[0])*(uint64(a[5])<<1) +
		uint64(a[1])*(uint64(a[4])<<1) +
		uint64(a[2])*(uint64(a[3])<<1)
	tmp[6] = uint64(a[0])*(uint64(a[6])<<1) +
		uint64(a[1])*(uint64(a[5])<<2) +
		uint64(a[2])*(uint64(a[4])<<1) +
		uint64(a[3])*(uint64(a[3])<<1)
	tmp[7] = uint64(a[0])*(uint64(a[7])<<1) +
		uint64(a[1])*(uint64(a[6])<<1) +
		uint64(a[2])*(uint64(a[5])<<1) +
		uint64(a[3])*(uint64(a[4])<<1)
	// tmp[8] has the greatest value of 2**61 + 2**60 + 2**61 + 2**60 + 2**60,
	// which is < 2**64 as required.
	tmp[8] = uint64(a[0])*(uint64(a[8])<<1) +
		uint64(a[1])*(uint64(a[7])<<2) +
		uint64(a[2])*(uint64(a[6])<<1) +
		uint64(a[3])*(uint64(a[5])<<2) +
		uint64(a[4])*uint64(a[4])
	tmp[9] = uint64(a[1])*(uint64(a[8])<<1) +
		uint64(a[2])*(uint64(a[7])<<1) +
		uint64(a[3])*(uint64(a[6])<<1) +
		uint64(a[4])*(uint64(a[5])<<1)
	tmp[10] = uint64(a[2])*(uint64(a[8])<<1) +
		uint64(a[3])*(uint64(a[7])<<2) +
		uint64(a[4])*(uint64(a[6])<<1) +
		uint64(a[5])*(uint64(a[5])<<1)
	tmp[11] = uint64(a[3])*(uint64(a[8])<<1) +
		uint64(a[4])*(uint64(a[7])<<1) +
		uint64(a[5])*(uint64(a[6])<<1)
	tmp[12] = uint64(a[4])*(uint64(a[8])<<1) +
		uint64(a[5])*(uint64(a[7])<<2) +
		uint64(a[6])*uint64(a[6])
	tmp[13] = uint64(a[5])*(uint64(a[8])<<1) +
		uint64(a[6])*(uint64(a[7])<<1)
	tmp[14] = uint64(a[6])*(uint64(a[8])<<1) +
		uint64(a[7])*(uint64(a[7])<<1)
	tmp[15] = uint64(a[7]) * (uint64(a[8]) << 1)
	tmp[16] = uint64(a[8]) * uint64(a[8])
	sm2ReduceDegree(b, &tmp)
}

// nonZeroToAllOnes returns:
//   0xffffffff for 0 < x <= 2**31
//   0 for x == 0 or x > 2**31.
func nonZeroToAllOnes(x uint32) uint32 {
	return ((x - 1) >> 31) - 1
}

var sm2Carry = [8 * 9]uint32{
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	0x2, 0x0, 0x1FFFFF00, 0x7FF, 0x0, 0x0, 0x0, 0x2000000, 0x0,
	0x4, 0x0, 0x1FFFFE00, 0xFFF, 0x0, 0x0, 0x0, 0x4000000, 0x0,
	0x6, 0x0, 0x1FFFFD00, 0x17FF, 0x0, 0x0, 0x0, 0x6000000, 0x0,
	0x8, 0x0, 0x1FFFFC00, 0x1FFF, 0x0, 0x0, 0x0, 0x8000000, 0x0,
	0xA, 0x0, 0x1FFFFB00, 0x27FF, 0x0, 0x0, 0x0, 0xA000000, 0x0,
	0xC, 0x0, 0x1FFFFA00, 0x2FFF, 0x0, 0x0, 0x0, 0xC000000, 0x0,
	0xE, 0x0, 0x1FFFF900, 0x37FF, 0x0, 0x0, 0x0, 0xE000000, 0x0,
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

// carry < 2 ^ 3
func sm2ReduceCarry(a *sm2FieldElement, carry uint32) {
	a[0] += sm2Carry[carry*9+0]
	a[2] += sm2Carry[carry*9+2]
	a[3] += sm2Carry[carry*9+3]
	a[7] += sm2Carry[carry*9+7]
}

func sm2ReduceDegree(a *sm2FieldElement, b *sm2LargeFieldElement) {
	var tmp [18]uint32
	var carry, x, xMask uint32

	// tmp
	// 0  | 1  | 2  | 3  | 4  | 5  | 6  | 7  | 8  |  9 | 10 ...
	// 29 | 28 | 29 | 28 | 29 | 28 | 29 | 28 | 29 | 28 | 29 ...
	tmp[0] = uint32(b[0]) & bottom29Bits
	tmp[1] = uint32(b[0]) >> 29
	tmp[1] |= (uint32(b[0]>>32) << 3) & bottom28Bits
	tmp[1] += uint32(b[1]) & bottom28Bits
	carry = tmp[1] >> 28
	tmp[1] &= bottom28Bits
	for i := 2; i < 17; i++ {
		tmp[i] = (uint32(b[i-2] >> 32)) >> 25
		tmp[i] += (uint32(b[i-1])) >> 28
		tmp[i] += (uint32(b[i-1]>>32) << 4) & bottom29Bits
		tmp[i] += uint32(b[i]) & bottom29Bits
		tmp[i] += carry
		carry = tmp[i] >> 29
		tmp[i] &= bottom29Bits

		i++
		if i == 17 {
			break
		}
		tmp[i] = uint32(b[i-2]>>32) >> 25
		tmp[i] += uint32(b[i-1]) >> 29
		tmp[i] += ((uint32(b[i-1] >> 32)) << 3) & bottom28Bits
		tmp[i] += uint32(b[i]) & bottom28Bits
		tmp[i] += carry
		carry = tmp[i] >> 28
		tmp[i] &= bottom28Bits
	}
	tmp[17] = uint32(b[15]>>32) >> 25
	tmp[17] += uint32(b[16]) >> 29
	tmp[17] += uint32(b[16]>>32) << 3
	tmp[17] += carry

	for i := 0; ; i += 2 {

		tmp[i+1] += tmp[i] >> 29
		x = tmp[i] & bottom29Bits
		tmp[i] = 0
		if x > 0 {
			set4 := uint32(0)
			set7 := uint32(0)
			xMask = nonZeroToAllOnes(x)
			tmp[i+2] += (x << 7) & bottom29Bits
			tmp[i+3] += x >> 22
			if tmp[i+3] < 0x10000000 {
				set4 = 1
				tmp[i+3] += 0x10000000 & xMask
				tmp[i+3] -= (x << 10) & bottom28Bits
			} else {
				tmp[i+3] -= (x << 10) & bottom28Bits
			}
			if tmp[i+4] < 0x20000000 {
				tmp[i+4] += 0x20000000 & xMask
				tmp[i+4] -= set4 // 借位
				tmp[i+4] -= x >> 18
				if tmp[i+5] < 0x10000000 {
					tmp[i+5] += 0x10000000 & xMask
					tmp[i+5]-- // 借位
					if tmp[i+6] < 0x20000000 {
						set7 = 1
						tmp[i+6] += 0x20000000 & xMask
						tmp[i+6]-- // 借位
					} else {
						tmp[i+6]-- // 借位
					}
				} else {
					tmp[i+5]--
				}
			} else {
				tmp[i+4] -= set4 // 借位
				tmp[i+4] -= x >> 18
			}
			if tmp[i+7] < 0x10000000 {
				tmp[i+7] += 0x10000000 & xMask
				tmp[i+7] -= set7
				tmp[i+7] -= (x << 24) & bottom28Bits
				tmp[i+8] += (x << 28) & bottom29Bits
				if tmp[i+8] < 0x20000000 {
					tmp[i+8] += 0x20000000 & xMask
					tmp[i+8]--
					tmp[i+8] -= x >> 4
					tmp[i+9] += ((x >> 1) - 1) & xMask
				} else {
					tmp[i+8]--
					tmp[i+8] -= x >> 4
					tmp[i+9] += (x >> 1) & xMask
				}
			} else {
				tmp[i+7] -= set7 // 借位
				tmp[i+7] -= (x << 24) & bottom28Bits
				tmp[i+8] += (x << 28) & bottom29Bits
				if tmp[i+8] < 0x20000000 {
					tmp[i+8] += 0x20000000 & xMask
					tmp[i+8] -= x >> 4
					tmp[i+9] += ((x >> 1) - 1) & xMask
				} else {
					tmp[i+8] -= x >> 4
					tmp[i+9] += (x >> 1) & xMask
				}
			}

		}

		if i+1 == 9 {
			break
		}

		tmp[i+2] += tmp[i+1] >> 28
		x = tmp[i+1] & bottom28Bits
		tmp[i+1] = 0
		if x > 0 {
			set5 := uint32(0)
			set8 := uint32(0)
			set9 := uint32(0)
			xMask = nonZeroToAllOnes(x)
			tmp[i+3] += (x << 7) & bottom28Bits
			tmp[i+4] += x >> 21
			if tmp[i+4] < 0x20000000 {
				set5 = 1
				tmp[i+4] += 0x20000000 & xMask
				tmp[i+4] -= (x << 11) & bottom29Bits
			} else {
				tmp[i+4] -= (x << 11) & bottom29Bits
			}
			if tmp[i+5] < 0x10000000 {
				tmp[i+5] += 0x10000000 & xMask
				tmp[i+5] -= set5 // 借位
				tmp[i+5] -= x >> 18
				if tmp[i+6] < 0x20000000 {
					tmp[i+6] += 0x20000000 & xMask
					tmp[i+6]-- // 借位
					if tmp[i+7] < 0x10000000 {
						set8 = 1
						tmp[i+7] += 0x10000000 & xMask
						tmp[i+7]-- // 借位
					} else {
						tmp[i+7]-- // 借位
					}
				} else {
					tmp[i+6]-- // 借位
				}
			} else {
				tmp[i+5] -= set5 // 借位
				tmp[i+5] -= x >> 18
			}
			if tmp[i+8] < 0x20000000 {
				set9 = 1
				tmp[i+8] += 0x20000000 & xMask
				tmp[i+8] -= set8
				tmp[i+8] -= (x << 25) & bottom29Bits
			} else {
				tmp[i+8] -= set8
				tmp[i+8] -= (x << 25) & bottom29Bits
			}
			if tmp[i+9] < 0x10000000 {
				tmp[i+9] += 0x10000000 & xMask
				tmp[i+9] -= set9 // 借位
				tmp[i+9] -= x >> 4
				tmp[i+10] += (x - 1) & xMask
			} else {
				tmp[i+9] -= set9 // 借位
				tmp[i+9] -= x >> 4
				tmp[i+10] += x & xMask
			}
		}
	}

	carry = uint32(0)
	for i := 0; i < 8; i++ {
		a[i] = tmp[i+9]
		a[i] += carry
		a[i] += (tmp[i+10] << 28) & bottom29Bits
		carry = a[i] >> 29
		a[i] &= bottom29Bits

		i++
		a[i] = tmp[i+9] >> 1
		a[i] += carry
		carry = a[i] >> 28
		a[i] &= bottom28Bits
	}
	a[8] = tmp[17]
	a[8] += carry
	carry = a[8] >> 29
	a[8] &= bottom29Bits
	sm2ReduceCarry(a, carry)
}

// X = a * R mod P
func sm2FromBig(X *sm2FieldElement, a *big.Int) {
	x := GetInt().Lsh(a, 257)
	x.Mod(x, sm2.P)
	for i := 0; i < 9; i++ {
		if bits := x.Bits(); len(bits) > 0 {
			X[i] = uint32(bits[0]) & bottom29Bits
		} else {
			X[i] = 0
		}
		x.Rsh(x, 29)
		i++
		if i == 9 {
			break
		}
		if bits := x.Bits(); len(bits) > 0 {
			X[i] = uint32(bits[0]) & bottom28Bits
		} else {
			X[i] = 0
		}
		x.Rsh(x, 28)
	}
	PutInt(x)
}

// X = a * R mod N
func sm2FromBigOrder(X *sm2FieldElement, a *big.Int) {
	x := new(big.Int).Lsh(a, 257)
	x.Mod(x, sm2.N)
	for i := 0; i < 9; i++ {
		if bits := x.Bits(); len(bits) > 0 {
			X[i] = uint32(bits[0]) & bottom29Bits
		} else {
			X[i] = 0
		}
		x.Rsh(x, 29)
		i++
		if i == 9 {
			break
		}
		if bits := x.Bits(); len(bits) > 0 {
			X[i] = uint32(bits[0]) & bottom28Bits
		} else {
			X[i] = 0
		}
		x.Rsh(x, 28)
	}
}

// X = r * R mod P
// r = X * R' mod P
func sm2ToBig(X *sm2FieldElement) *big.Int {
	r, tm := new(big.Int), GetInt()
	r.SetInt64(int64(X[8]))
	for i := 7; i >= 0; i-- {
		if (i & 1) == 0 {
			r.Lsh(r, 29)
		} else {
			r.Lsh(r, 28)
		}
		tm.SetInt64(int64(X[i]))
		r.Add(r, tm)
	}
	r.Mul(r, sm2RInverse)
	r.Mod(r, sm2.P)
	PutInt(tm)
	return r
}

// X = r * R mod N
// r = X * R' mod N
func sm2ToBigOrder(X *sm2FieldElement) *big.Int {
	r, tm := new(big.Int), new(big.Int)
	r.SetInt64(int64(X[8]))
	for i := 7; i >= 0; i-- {
		if (i & 1) == 0 {
			r.Lsh(r, 29)
		} else {
			r.Lsh(r, 28)
		}
		tm.SetInt64(int64(X[i]))
		r.Add(r, tm)
	}
	r.Mul(r, sm2RInverse)
	r.Mod(r, sm2.N)
	return r
}

func sm2InversP(out, in *sm2FieldElement) {
	var x1, x2, x4, x6, x7, x8, x15, x30, x31, x32 sm2FieldElement
	copy(x1[:], (*in)[:])
	sm2Square(&x2, in)
	sm2Mul(&x2, &x2, in)

	sm2SquareTimes(&x4, &x2, 2)
	sm2Mul(&x4, &x4, &x2)

	sm2SquareTimes(&x6, &x4, 2)
	sm2Mul(&x6, &x6, &x2)

	sm2Square(&x7, &x6)
	sm2Mul(&x7, &x7, in)

	sm2SquareTimes(&x8, &x7, 1)
	sm2Mul(&x8, &x8, in)

	sm2SquareTimes(&x15, &x8, 7)
	sm2Mul(&x15, &x15, &x7)

	sm2SquareTimes(&x30, &x15, 15)
	sm2Mul(&x30, &x30, &x15)

	sm2SquareTimes(&x31, &x30, 1)
	sm2Mul(&x31, &x31, in) //x31

	sm2SquareTimes(&x32, &x31, 1)
	sm2Mul(&x32, &x32, in)

	sm2SquareTimes(out, &x31, 33)
	sm2Mul(out, out, &x32)

	sm2SquareTimes(out, out, 32)
	sm2Mul(out, out, &x32)

	sm2SquareTimes(out, out, 32)
	sm2Mul(out, out, &x32)

	sm2SquareTimes(out, out, 32)
	sm2Mul(out, out, &x32)

	sm2SquareTimes(out, out, 64)
	sm2Mul(out, out, &x32)

	sm2SquareTimes(out, out, 30)
	sm2Mul(out, out, &x30)

	sm2SquareTimes(out, out, 2)
	sm2Mul(out, out, &x1)
}

//fixme: 速度不如big。int？
func sm2SquareTimes(b, a *sm2FieldElement, n int) {
	sm2Square(b, a)
	for i := 1; i < n; i++ {
		sm2Square(b, b)
	}
}

func sm2StorePoint(r *[16 * 3]sm2FieldElement, index int, x, y, z *sm2FieldElement) {
	copy(r[index*3+0][:], x[:])
	copy(r[index*3+1][:], y[:])
	copy(r[index*3+2][:], z[:])
}
func boothW5(in uint) (int, int) {
	var s = ^((in >> 5) - 1)
	var d = (1 << 6) - in - 1
	d = (d & s) | (in & (^s))
	d = (d >> 1) + (d & 1)
	return int(d), int(s & 1)
}
func movCond(x3, y3, z3, x1, y1, z1, x2, y2, z2 *sm2FieldElement, cond int) {
	if cond == 0 {
		copy(x3[:], x2[:])
		copy(y3[:], y2[:])
		copy(z3[:], z2[:])
		return
	}
	copy(x3[:], x1[:])
	copy(y3[:], y1[:])
	copy(z3[:], z1[:])
}
func sm2Select(x, y, z *sm2FieldElement, table *[16 * 3]sm2FieldElement, sel int) {
	if sel == 0 {
		*x = sm2FieldElement{0, 0, 0, 0, 0, 0, 0, 0, 0}
		*y = sm2FieldElement{0, 0, 0, 0, 0, 0, 0, 0, 0}
		*z = sm2FieldElement{0, 0, 0, 0, 0, 0, 0, 0, 0}
		//*z = sm2FieldElement{0x2,0,0x1fffff00, 0x7ff,0, 0, 0,0x2000000, 0x0}
		return
	}
	copy(x[:], table[(sel-1)*3+0][:])
	copy(y[:], table[(sel-1)*3+1][:])
	copy(z[:], table[(sel-1)*3+2][:])
}
func sm2ScalarMult2(xOut, yOut, zOut, x, y *sm2FieldElement, scalar *[8]uint32) {
	// precomp is a table of precomputed points that stores powers of p
	// from p^1 to p^16.
	var precomp [16 * 3]sm2FieldElement
	var t0, t1, t2, t3 [3]sm2FieldElement
	// Prepare the table
	z := &sm2FieldElement{0x2, 0, 0x1fffff00, 0x7ff, 0, 0, 0, 0x2000000, 0x0}
	sm2StorePoint(&precomp, 0, x, y, z) // 1

	sm2PointDouble(&t0[0], &t0[1], &t0[2], x, y, z)
	sm2PointDouble(&t1[0], &t1[1], &t1[2], &t0[0], &t0[1], &t0[2])
	sm2PointDouble(&t2[0], &t2[1], &t2[2], &t1[0], &t1[1], &t1[2])
	sm2PointDouble(&t3[0], &t3[1], &t3[2], &t2[0], &t2[1], &t2[2])
	sm2StorePoint(&precomp, 1, &t0[0], &t0[1], &t0[2])  // 2
	sm2StorePoint(&precomp, 3, &t1[0], &t1[1], &t1[2])  // 4
	sm2StorePoint(&precomp, 7, &t2[0], &t2[1], &t2[2])  // 8
	sm2StorePoint(&precomp, 15, &t3[0], &t3[1], &t3[2]) // 16

	sm2PointAdd(&t0[0], &t0[1], &t0[2], x, y, z, &t0[0], &t0[1], &t0[2])
	sm2PointAdd(&t1[0], &t1[1], &t1[2], x, y, z, &t1[0], &t1[1], &t1[2])
	sm2PointAdd(&t2[0], &t2[1], &t2[2], x, y, z, &t2[0], &t2[1], &t2[2])

	sm2StorePoint(&precomp, 2, &t0[0], &t0[1], &t0[2]) // 3
	sm2StorePoint(&precomp, 4, &t1[0], &t1[1], &t1[2]) // 5
	sm2StorePoint(&precomp, 8, &t2[0], &t2[1], &t2[2]) // 9

	sm2PointDouble(&t0[0], &t0[1], &t0[2], &t0[0], &t0[1], &t0[2])
	sm2PointDouble(&t1[0], &t1[1], &t1[2], &t1[0], &t1[1], &t1[2])
	sm2StorePoint(&precomp, 5, &t0[0], &t0[1], &t0[2]) // 6
	sm2StorePoint(&precomp, 9, &t1[0], &t1[1], &t1[2]) // 10

	sm2PointAdd(&t0[0], &t0[1], &t0[2], x, y, z, &t2[0], &t2[1], &t2[2])
	sm2PointAdd(&t1[0], &t1[1], &t1[2], x, y, z, &t1[0], &t1[1], &t1[2])
	sm2StorePoint(&precomp, 6, &t2[0], &t2[1], &t2[2])  // 7
	sm2StorePoint(&precomp, 10, &t1[0], &t1[1], &t1[2]) // 11

	sm2PointDouble(&t0[0], &t0[1], &t0[2], &t0[0], &t0[1], &t0[2])
	sm2PointDouble(&t2[0], &t2[1], &t2[2], &t2[0], &t2[1], &t2[2])
	sm2StorePoint(&precomp, 11, &t0[0], &t0[1], &t0[2]) // 12
	sm2StorePoint(&precomp, 13, &t2[0], &t2[1], &t2[2]) // 14

	sm2PointAdd(&t0[0], &t0[1], &t0[2], x, y, z, &t0[0], &t0[1], &t0[2])
	sm2PointAdd(&t2[0], &t2[1], &t2[2], x, y, z, &t2[0], &t2[1], &t2[2])
	sm2StorePoint(&precomp, 12, &t0[0], &t0[1], &t0[2]) // 13
	sm2StorePoint(&precomp, 14, &t2[0], &t2[1], &t2[2]) // 15

	// Start scanning the window from top bit
	index := uint(254)
	var sel, sign int

	wvalue := (scalar[index/32] >> (index % 32)) & 0x3f
	sel, _ = boothW5(uint(wvalue))
	sm2Select(xOut, yOut, zOut, &precomp, sel)

	zero := sel

	for index > 4 {

		index -= 5
		sm2PointDouble(xOut, yOut, zOut, xOut, yOut, zOut)
		sm2PointDouble(xOut, yOut, zOut, xOut, yOut, zOut)
		sm2PointDouble(xOut, yOut, zOut, xOut, yOut, zOut)
		sm2PointDouble(xOut, yOut, zOut, xOut, yOut, zOut)
		sm2PointDouble(xOut, yOut, zOut, xOut, yOut, zOut)

		if index < 224 {
			wvalue = ((scalar[index/32] >> (index % 32)) + (scalar[index/32+1] << (32 - (index % 32)))) & 0x3f
		} else {
			wvalue = (scalar[index/32] >> (index % 32)) & 0x3f
		}

		sel, sign = boothW5(uint(wvalue))
		sm2Select(&t0[0], &t0[1], &t0[2], &precomp, sel)
		negCond(&t0[1], sign)

		sm2PointAdd(&t0[0], &t0[1], &t0[2], xOut, yOut, zOut, &t1[0], &t1[1], &t1[2])
		movCond(&t1[0], &t1[1], &t1[2], &t1[0], &t1[1], &t1[2], xOut, yOut, zOut, sel)
		movCond(xOut, yOut, zOut, &t1[0], &t1[1], &t1[2], &t0[0], &t0[1], &t0[2], zero)
		zero |= sel
	}

	sm2PointDouble(xOut, yOut, zOut, xOut, yOut, zOut)
	sm2PointDouble(xOut, yOut, zOut, xOut, yOut, zOut)
	sm2PointDouble(xOut, yOut, zOut, xOut, yOut, zOut)
	sm2PointDouble(xOut, yOut, zOut, xOut, yOut, zOut)
	sm2PointDouble(xOut, yOut, zOut, xOut, yOut, zOut)

	wvalue = (scalar[0] << 1) & 0x3f
	sel, sign = boothW5(uint(wvalue))

	sm2Select(&t0[0], &t0[1], &t0[2], &precomp, sel)
	negCond(&t0[1], sign)
	sm2PointAdd(xOut, yOut, zOut, &t0[0], &t0[1], &t0[2], &t1[0], &t1[1], &t1[2])
	movCond(&t1[0], &t1[1], &t1[2], &t1[0], &t1[1], &t1[2], xOut, yOut, zOut, sel)
	movCond(xOut, yOut, zOut, &t1[0], &t1[1], &t1[2], &t0[0], &t0[1], &t0[2], zero)
}

// scalarIsZero returns 1 if scalar represents the zero value, and zero
// otherwise.
func scalarIsZero(scalar *[8]uint32) int {
	return uint32IsZero(scalar[0] | scalar[1] | scalar[2] | scalar[3] | scalar[4] | scalar[5] | scalar[6] | scalar[7])
}

// uint64IsZero returns 1 if x is zero and zero otherwise.
func uint32IsZero(x uint32) int {
	x = ^x
	x &= x >> 16
	x &= x >> 8
	x &= x >> 4
	x &= x >> 2
	x &= x >> 1
	return int(x & 1)
}
func isZeroPoint(x, y, z *sm2FieldElement) bool {
	if bytes.Equal(sm2ToBig(x).Bytes(), []byte{0}) && bytes.Equal(sm2ToBig(y).Bytes(), []byte{0}) && bytes.Equal(sm2ToBig(z).Bytes(), []byte{0}) {
		return true
	}
	return false
}
func sm2CombinedMult(X, Y *big.Int, baseScalar, scalar *big.Int) (*big.Int, *big.Int) {
	var r1, r2 [3]sm2FieldElement
	var newScalar [8]uint32
	sm2GetScalar2(&newScalar, baseScalar.Bytes())
	r1IsInfinity := scalarIsZero(&newScalar)
	sm2BaseMult2(&r1[0], &r1[1], &r1[2], &newScalar)

	sm2GetScalar2(&newScalar, scalar.Bytes())
	r2IsInfinity := scalarIsZero(&newScalar)

	sm2FromBig(&r2[0], X)
	sm2FromBig(&r2[1], Y)
	r2[2] = sm2FieldElement{0x2, 0, 0x1fffff00, 0x7ff, 0, 0, 0, 0x2000000, 0x0}
	sm2ScalarMult2(&r2[0], &r2[1], &r2[2], &r2[0], &r2[1], &newScalar)

	var sum [3]sm2FieldElement
	sm2PointAdd(&r1[0], &r1[1], &r1[2], &r2[0], &r2[1], &r2[2], &sum[0], &sum[1], &sum[2])
	if isZeroPoint(&sum[0], &sum[1], &sum[2]) {
		sm2PointDouble(&sum[0], &sum[1], &sum[2], &r1[0], &r1[1], &r1[2])
	}
	if r2IsInfinity == 1 {
		sum = r1
	}

	if r1IsInfinity == 1 {
		sum = r2
	}

	zz := sm2ToBig(&sum[2])
	zz.ModInverse(zz, sm2.P)
	sm2FromBig(&sum[2], zz)
	sm2Square(&sum[2], &sum[2])
	sm2Mul(&sum[0], &sum[0], &sum[2])

	return sm2ToBig(&sum[0]), nil
}
