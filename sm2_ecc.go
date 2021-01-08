package gm

import (
	"bytes"
	"crypto/elliptic"
	"errors"
	"github.com/meshplus/crypto-gm/internal/sm2"
	"github.com/meshplus/crypto-gm/internal/sm3"
	"io"
	"math/big"
)

/*
 *  x
 *  y
 *  CipherText
 *  hash
 */

//Encrypt sm2 ecc encrypt
func Encrypt(pub *SM2PublicKey, data []byte, ivReader io.Reader) ([]byte, error) {
	length := len(data)
	curve := sm2.Sm2()
	k, err := randFieldElement(curve, ivReader)
	if err != nil {
		return nil, err
	}
	x1, y1 := curve.ScalarBaseMult(k.Bytes()) //x1,x2 = kG
	xPara := new(big.Int).SetBytes(pub.X[:])
	yPara := new(big.Int).SetBytes(pub.Y[:])
	x2, y2 := curve.ScalarMult(xPara, yPara, k.Bytes()) //x2,y2 = kP
	bufkG := make([]byte, 64)                           //x1 || y1
	bufkP := make([]byte, 64)                           //x2 || y2
	x1Buf := x1.Bytes()
	y1Buf := y1.Bytes()
	x2Buf := x2.Bytes()
	y2Buf := y2.Bytes()
	copy(bufkG[32-len(x1Buf):], x1Buf)
	copy(bufkG[64-len(y1Buf):], y1Buf)
	copy(bufkP[32-len(x2Buf):], x2Buf)
	copy(bufkP[64-len(y2Buf):], y2Buf)
	ct, ok := kdf(bufkP[:32], bufkP[32:], length) //
	if !ok {
		return nil, errors.New("try change random")
	}

	tm := bytes.Join([][]byte{bufkP[:32], data, bufkP[32:]}, nil) // x2 || data || y2
	h := sm3.New()
	_, _ = h.Write(tm)
	dist := h.Sum(nil) //H(x2 || data || y2)

	for i := 0; i < length; i++ {
		ct[i] ^= data[i]
	}
	return bytes.Join([][]byte{{0x04}, bufkG, ct, dist}, nil), nil
}

//Decrypt sm2 ecc decrypt
func Decrypt(priv *SM2PrivateKey, data []byte) ([]byte, error) {
	data = data[1:]
	length := len(data) - 96
	curve := sm2.Sm2()
	x := new(big.Int).SetBytes(data[:32])
	y := new(big.Int).SetBytes(data[32:64]) //kG
	x2, y2 := curve.ScalarMult(x, y, priv.K[:])
	x2Buf := x2.Bytes() //kP
	y2Buf := y2.Bytes()

	bufkP := make([]byte, 64)
	copy(bufkP[32-len(x2Buf):], x2Buf)
	copy(bufkP[64-len(y2Buf):], y2Buf)

	c, ok := kdf(bufkP[:32], bufkP[32:], length)
	if !ok {
		return nil, errors.New("decrypt: failed to decrypt, kdf error")
	}
	for i := 0; i < length; i++ {
		c[i] ^= data[i+64]
	}
	tm := bytes.Join([][]byte{bufkP[:32], c, bufkP[32:]}, nil)

	h := sm3.New()
	_, _ = h.Write(tm)
	dist := h.Sum(nil)
	if bytes.Compare(dist, data[length+64:]) != 0 {
		return c, errors.New("decrypt: failed to decrypt, mac error")
	}
	return c, nil
}

var one = big.NewInt(1)

func randFieldElement(c elliptic.Curve, rand io.Reader) (k *big.Int, err error) {
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	_, err = io.ReadFull(rand, b)
	if err != nil {
		return
	}
	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}

func kdf(x, y []byte, length int) ([]byte, bool) {
	var c []byte
	ct := 1
	h := sm3.New()
	for i, j := 0, (length+31)/32; i < j; i++ {
		h.Reset()
		_, _ = h.Write(x)
		_, _ = h.Write(y)
		_, _ = h.Write(intToBytes(ct))
		hash := h.Sum(nil)
		if i+1 == j && length%32 != 0 {
			c = append(c, hash[:length%32]...)
		} else {
			c = append(c, hash...)
		}
		ct++
	}
	for i := 0; i < length; i++ {
		if c[i] != 0 {
			return c, true
		}
	}
	return c, false
}
func sm2DHKdf(in []byte, length int) []byte {
	var c []byte
	ct := 1
	h := sm3.New()
	for i, j := 0, (length+31)/32; i < j; i++ {
		h.Reset()
		_, _ = h.Write(in)
		_, _ = h.Write(intToBytes(ct))
		hash := h.Sum(nil)
		if i+1 == j && length%32 != 0 {
			c = append(c, hash[:length%32]...)
		} else {
			c = append(c, hash...)
		}
		ct++
	}
	return c
}
func intToBytes(x int) []byte {
	var b = make([]byte, 4)
	b[0] = byte(x >> 24)
	b[1] = byte(x >> 16)
	b[2] = byte(x >> 8)
	b[3] = byte(x)
	return b
}
