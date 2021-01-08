package gm

import (
	"github.com/meshplus/crypto-gm/internal/sm3"
	"hash"
)

//Hasher thw return value of function NewHasher
type Hasher struct {
	inner hash.Hash
	dirty bool
}

//NewSM3Hasher instruct a SM# Hasher
func NewSM3Hasher() *Hasher {
	return &Hasher{
		inner: sm3.New(),
	}
}

//Hash compute hash
func (h *Hasher) Hash(msg []byte) (hash []byte, err error) {
	h.cleanIfDirty()
	h.dirty = true
	if _, err := h.inner.Write(msg); err != nil {
		return nil, err
	}
	return h.inner.Sum(nil), nil
}

//BatchHash hash with two-dimensional array
func (h *Hasher) BatchHash(msg [][]byte) (hash []byte, err error) {
	h.cleanIfDirty()
	h.dirty = true
	for i := range msg {
		_, err := h.inner.Write(msg[i])
		if err != nil {
			return nil, err
		}
	}
	return h.inner.Sum(nil), nil
}

func (h *Hasher) cleanIfDirty() {
	if h.dirty {
		h.inner.Reset()
	}
}

//HashBeforeSM2  If hash is for using sm2, invoke this method.
func HashBeforeSM2(pub *SM2PublicKey, msg []byte) []byte {
	return sm3.SignHashSM3(pub.X[:], pub.Y[:], msg)
}

//GetSM3Hasher get hash.Hash
func GetSM3Hasher() hash.Hash {
	return sm3.New()
}
