//+build !cuda

package gm

import "github.com/meshplus/crypto-gm/internal/sm2"

// Verify verify the signature by SM2PublicKey self, so the first parameter will be ignored.
func (key *SM2PublicKey) Verify(_ []byte, signature, digest []byte) (valid bool, err error) {
	return sm2.VerifySignature(signature, digest, key.X[:], key.Y[:])
}
