package internal

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
)

/*
func Sm2_32bit() elliptic.Curve => Sm2_32bit, curve.go
func Sign_32bit(dgst []byte, reader io.Reader, key []byte) ([]byte, uint8, error)
func VerifySignature_32bit(sig, dgst []byte, X []byte, Y []byte) (bool, error)
func GetBatchHeap_32bit() interface{}
func PutBatchHeap_32bit(in interface{})
func BatchVerifyInit_32bit(ctxin interface{}, publicKey, signature, msg [][]byte) bool
func BatchVerifyEnd_32bit(ctxin interface{}) bool
func BatchVerify_32bit(publicKey, signature, msg [][]byte) error
*/

var (
	oneBig  = big.NewInt(1)
	zeroBig = big.NewInt(0)
)

//Sign_32bit to sign dgst
func Sign_32bit(dgst []byte, reader io.Reader, key []byte) ([]byte, uint8, error) {
	e := GetInt().SetBytes(dgst)
	keyBig := GetInt().SetBytes(key)
	r, s, randK := GetInt(), GetInt(), GetInt()
	var err error
	var flag uint8
	for {
		for {
			randK, err = rand.Int(reader, Sm2_32bit().Params().N)
			if err != nil {
				return nil, 0, err
			}
			if randK.Cmp(zeroBig) == 0 { //k ∈ [1,n-1]
				return nil, 0, fmt.Errorf("zero rander")
			}
			x, y := Sm2_32bit().ScalarBaseMult(randK.Bytes())

			ny := GetInt().Sub(Sm2_32bit().Params().P, y)
			if y.Cmp(ny) > 0 { // y1 > ny
				flag = 1
			} else {
				flag = 0
			}
			PutInt(ny)

			r.Add(e, x)
			r.Mod(r, Sm2_32bit().Params().N)
			t := GetInt().Add(r, randK)
			t.Mod(t, Sm2_32bit().Params().N)
			if r.Sign() != 0 && t.Sign() != 0 {
				PutInt(t)
				break
			}
			PutInt(t)
		}
		s.Add(oneBig, keyBig).Mod(s, Sm2_32bit().Params().N)
		s.ModInverse(s, Sm2_32bit().Params().N)
		keyBig.Mul(r, keyBig)
		randK.Sub(randK, keyBig)
		s.Mul(s, randK)
		s.Mod(s, Sm2_32bit().Params().N)
		if s.Sign() != 0 {
			break
		}
	}
	ret := MarshalSig(r.Bytes(), s.Bytes())
	PutInt(r)
	PutInt(s)
	PutInt(e)
	PutInt(keyBig)
	PutInt(randK)
	return ret, flag, nil
}

//VerifySignature_32bit to verify a signature and return error
func VerifySignature_32bit(sig, dgst []byte, X []byte, Y []byte) (bool, error) {
	var head int
	for head < len(sig) && sig[head] != 0x30 {
		head++
	}
	sig = sig[head:]
	r, s := Unmarshal(sig)
	ss := GetInt().SetBytes(s)
	rr := GetInt().SetBytes(r)
	if ss.Cmp(Sm2_32bit().Params().N) >= 0 || rr.Cmp(Sm2_32bit().Params().N) >= 0 {
		return false, errors.New("invalid signature")
	}
	e := GetInt().SetBytes(dgst)
	t := GetInt().Add(ss, rr)
	t.Mod(t, Sm2_32bit().Params().N)
	if t.Sign() == 0 {
		return false, errors.New("invalid signature")
	}
	xBig := GetInt().SetBytes(X)
	yBig := GetInt().SetBytes(Y)
	x, _ := sm2CombinedMult(xBig, yBig, ss, t)
	e.Add(e, x)
	e.Mod(e, Sm2_32bit().Params().N)
	ret := e.Cmp(rr) != 0

	PutInt(rr)
	PutInt(ss)
	PutInt(e)
	PutInt(t)
	PutInt(xBig)
	PutInt(yBig)
	if ret {
		return false, errors.New("invalid signature")
	}
	return true, nil
}
