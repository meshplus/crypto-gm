package sm2

import (
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/meshplus/crypto-gm/internal/sm2/internal"
	"io"
	"math/big"
)

var (
	n       = &[4]uint64{0x53BBF40939D54123, 0x7203DF6B21C6052B, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFEFFFFFFFF}
	zeroBig = big.NewInt(0)
)

//sign_64bit to sign dgst
func sign_64bit(dgst []byte, reader io.Reader, key []byte) ([]byte, uint8, error) {
	var rs [64]byte
	rr, ss := rs[:32], rs[32:]
	e, d, r, randK, t, s := [4]uint64{}, [4]uint64{}, [4]uint64{}, [4]uint64{}, [4]uint64{}, [4]uint64{}
	big2little(&e, dgst)
	big2little(&d, key)
	var flag uint8
	for {
		for {
			randKBig, err := rand.Int(reader, Sm2().Params().N)
			if err != nil {
				return nil, 0, err
			}
			if randKBig.Cmp(zeroBig) == 0 { //k ∈ [1,n-1]
				return nil, 0, fmt.Errorf("zero rander")
			}
			big2little(&randK, randKBig.Bytes())
			//(x1,y1)=[k]G
			x1, y1 := Sm2().ScalarBaseMult(randKBig.Bytes())
			ny, y11 := [4]uint64{}, [4]uint64{}
			fromBig(&ny, y1)
			p256NegCond(&ny, 1)
			fromBig(&y11, y1)
			if biggerThan(&y11, &ny) { // y1 > ny
				flag = 1
			} else {
				flag = 0
			}

			big2little(&r, x1.Bytes())
			orderAdd(&r, &r, &e)
			orderAdd(&t, &r, &randK)

			if (r[0]|r[1]|r[2]|r[3])&(t[0]|t[1]|t[2]|t[3]) != 0 { //r!=0 && r+e != 0
				break
			}
		}
		orderAdd(&s, &one, &d)
		ordInverse(&s)
		orderMul(&d, &d, &RRN)
		orderMul(&d, &r, &d)
		orderSub(&randK, &randK, &d)
		orderMul(&s, &s, &randK)
		if s[0]|s[1]|s[2]|s[3] != 0 { //s != 0
			break
		}
	}
	little2big(rr, &r)
	little2big(ss, &s)
	return internal.MarshalSig(rr, ss), flag, nil
}

//verifySignature_64bit to verify a signature and return error
func verifySignature_64bit(sig, dgst []byte, X []byte, Y []byte) (bool, error) {
	head := 0
	for head < len(sig) && sig[head] != 0x30 {
		head++
	}
	sig = sig[head:]
	r, s := internal.Unmarshal(sig)
	rr, ss, e, t, x, y := [4]uint64{}, [4]uint64{}, [4]uint64{}, [4]uint64{}, [4]uint64{}, [4]uint64{}
	big2little(&rr, r)
	big2little(&ss, s)
	if biggerThan(&rr, n) || biggerThan(&ss, n) {
		return false, errors.New("invalid signature")
	}
	big2little(&e, dgst[:])
	orderAdd(&t, &ss, &rr)

	if t[0] == 0 && t[1] == 0 && t[2] == 0 && t[3] == 0 {
		return false, errors.New("invalid signature")
	}
	big2little(&x, X)
	big2little(&y, Y)
	sm2.combinedMult(&x, &y, &ss, &t)
	orderAdd(&e, &e, &x)
	if e[0] == rr[0] && e[1] == rr[1] && e[2] == rr[2] && e[3] == rr[3] {
		return true, nil
	}

	return false, errors.New("invalid signature")
}
