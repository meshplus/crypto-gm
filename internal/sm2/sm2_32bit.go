package sm2

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
)

var (
	oneBig, _  = new(big.Int).SetString("1", 10)
	zeroBig, _ = new(big.Int).SetString("0", 10)
)

//Sign to sign dgst
func Sign(dgst []byte, reader io.Reader, key []byte) ([]byte, uint8, error) {
	e := new(big.Int).SetBytes(dgst)
	keyBig := new(big.Int).SetBytes(key)
	r := new(big.Int)
	s := new(big.Int)
	randK := new(big.Int)
	var err error
	var flag uint8
	for {
		for {
			randK, err = rand.Int(reader, Sm2().Params().N)
			if err != nil {
				return nil, 0, err
			}
			if randK.Cmp(zeroBig) == 0 { //k ∈ [1,n-1]
				return nil, 0, fmt.Errorf("zero rander")
			}
			x, y := Sm2().ScalarBaseMult(randK.Bytes())

			ny := new(big.Int).Sub(Sm2().Params().P, y)
			if y.Cmp(ny) > 0 { // y1 > ny
				flag = 1
			} else {
				flag = 0
			}

			r.Add(e, x)
			r.Mod(r, Sm2().Params().N)
			t := new(big.Int).Add(r, randK)
			t.Mod(t, Sm2().Params().N)
			if r.Sign() != 0 && t.Sign() != 0 {
				break
			}
		}
		s.Add(oneBig, keyBig).Mod(s, Sm2().Params().N)
		s.ModInverse(s, Sm2().Params().N)
		keyBig.Mul(r, keyBig)
		randK.Sub(randK, keyBig)
		s.Mul(s, randK)
		s.Mod(s, Sm2().Params().N)
		if s.Sign() != 0 {
			break
		}
	}

	return marshal(r.Bytes(), s.Bytes()), flag, nil
}

//VerifySignature to verify a signature and return error
func VerifySignature(sig, dgst []byte, X []byte, Y []byte) (bool, error) {
	head := 0
	for head < len(sig) && sig[head] != 0x30 {
		head++
	}
	sig = sig[head:]
	r, s := unMarshal(sig)
	ss := new(big.Int).SetBytes(s)
	rr := new(big.Int).SetBytes(r)
	if ss.Cmp(Sm2().Params().N) >= 0 || rr.Cmp(Sm2().Params().N) >= 0 {
		return false, errors.New("invalid signature")
	}
	e := new(big.Int).SetBytes(dgst)
	t := new(big.Int).Add(ss, rr)
	t.Mod(t, Sm2().Params().N)
	if t.Sign() == 0 {
		return false, errors.New("invalid signature")
	}
	xBig := new(big.Int).SetBytes(X)
	yBig := new(big.Int).SetBytes(Y)
	x, _ := sm2CombinedMult(xBig, yBig, ss, t)
	e.Add(e, x)
	e.Mod(e, Sm2().Params().N)
	if e.Cmp(rr) != 0 {
		return false, errors.New("invalid signature")
	}
	return true, nil
}
