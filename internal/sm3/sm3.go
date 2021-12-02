package sm3

import "encoding/binary"

//nolint
func update_32bit(digest *[8]uint32, msg, end []byte) {
	var w [68]uint32
	var w1 [64]uint32
	//note 为了兼容64为的接口，在64为情况下这样操作可以节省一次append
	msg = append(msg, end...)
	a, b, c, d, e, f, g, h := digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7]
	for len(msg) >= 64 {
		for i := 0; i < 16; i++ {
			w[i] = binary.BigEndian.Uint32(msg[4*i : 4*(i+1)])
		}
		for i := 16; i < 68; i++ {
			w[i] = p1(w[i-16]^w[i-9]^leftRotate(w[i-3], 15)) ^ leftRotate(w[i-13], 7) ^ w[i-6]
		}
		for i := 0; i < 64; i++ {
			w1[i] = w[i] ^ w[i+4]
		}
		A, B, C, D, E, F, G, H := a, b, c, d, e, f, g, h
		for i := 0; i < 16; i++ {
			SS1 := leftRotate(leftRotate(A, 12)+E+leftRotate(0x79cc4519, uint32(i)), 7)
			SS2 := SS1 ^ leftRotate(A, 12)
			TT1 := ff0(A, B, C) + D + SS2 + w1[i]
			TT2 := gg0(E, F, G) + H + SS1 + w[i]
			D = C
			C = leftRotate(B, 9)
			B = A
			A = TT1
			H = G
			G = leftRotate(F, 19)
			F = E
			E = p0(TT2)
		}
		for i := 16; i < 64; i++ {
			SS1 := leftRotate(leftRotate(A, 12)+E+leftRotate(0x7a879d8a, uint32(i)), 7)
			SS2 := SS1 ^ leftRotate(A, 12)
			TT1 := ff1(A, B, C) + D + SS2 + w1[i]
			TT2 := gg1(E, F, G) + H + SS1 + w[i]
			D = C
			C = leftRotate(B, 9)
			B = A
			A = TT1
			H = G
			G = leftRotate(F, 19)
			F = E
			E = p0(TT2)
		}
		a ^= A
		b ^= B
		c ^= C
		d ^= D
		e ^= E
		f ^= F
		g ^= G
		h ^= H
		msg = msg[64:]
	}
	digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7] = a, b, c, d, e, f, g, h
}

func ff0(x, y, z uint32) uint32 { return x ^ y ^ z }

func ff1(x, y, z uint32) uint32 { return (x & y) | (x & z) | (y & z) }

func gg0(x, y, z uint32) uint32 { return x ^ y ^ z }

func gg1(x, y, z uint32) uint32 { return (x & y) | (^x & z) }

func p0(x uint32) uint32 { return x ^ leftRotate(x, 9) ^ leftRotate(x, 17) }

func p1(x uint32) uint32 { return x ^ leftRotate(x, 15) ^ leftRotate(x, 23) }

func leftRotate(x uint32, i uint32) uint32 { return x<<(i%32) | x>>(32-i%32) }
