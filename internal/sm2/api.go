package sm2

import (
	"crypto/elliptic"
	"github.com/meshplus/crypto-gm/internal/sm2/internal"
	"io"
)

/*
API
func Sm2() elliptic.Curve
func Sign(dgst []byte, reader io.Reader, key []byte) ([]byte, uint8, error)
func verifySignature(sig, dgst []byte, X []byte, Y []byte) (bool, error)
*/

func Sm2() elliptic.Curve {
	return internal.Sm2_32bit()
}

func Sign(dgst []byte, reader io.Reader, key []byte) ([]byte, uint8, error) {
	return internal.Sign_32bit(dgst, reader, key)
}
func VerifySignature(sig, dgst []byte, X []byte, Y []byte) (bool, error) {
	return internal.VerifySignature_32bit(sig, dgst, X, Y)
}

//MarshalSig marshal signature
func MarshalSig(x, y []byte) []byte

//Unmarshal unmarshal signature
func Unmarshal(in []byte) (x []byte, y []byte)
