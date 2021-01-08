package gm

import (
	"crypto/rand"
	"errors"
	"io"
)

//SM2 SM2 instance is a tool to sign and verify.
// You can sign and verify via SM2PrivateKey and SM2PublicKey, SM2 instance is just a package of SM2PrivateKey's Sign and SM2PublicKey's Verify.
// If you need revoke Sign or Verify at a sepcific Key many times, we recommend using SM2PrivateKey and SM2PublicKey, which avoid decode and alloc repeatedly.
// All in all, SM2 is convenient; SM2PrivateKey and SM2PublicKey are faster.
type SM2 struct {
}

//NewSM2 get a SM2 instance, input parameter is algorithm type
func NewSM2() *SM2 {
	return &SM2{}
}

//Sign get signature to digest, K is the private key
func (sv *SM2) Sign(k []byte, digest []byte, _ io.Reader) (signature []byte, err error) {
	return new(SM2PrivateKey).FromBytes(k).CalculatePublicKey().Sign(rand.Reader, digest, nil)
}

//Verify verify signature ,K is the public key
func (sv *SM2) Verify(k []byte, signature, digest []byte) (valid bool, err error) {
	pk := new(SM2PublicKey).FromBytes(k)
	if pk == nil {
		return false, errors.New("is not sm2 public key")
	}
	return pk.Verify(nil, signature, digest)
}
