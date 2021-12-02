package gm

import (
	"fmt"
	"github.com/meshplus/crypto-gm/internal/sm3"
	"hash"
)

var errPrefix = fmt.Errorf("publicKey is not start with 0x04")

//IDHasher thw return value of function NewHasher
type IDHasher struct {
	inner    hash.Hash
	init     [32]byte
	sm2PkBuf [65]byte
	dirty    bool
	index    uint8 //index of sm2PkBuf
}

//NewSM3IDHasher instruct a SM# Hasher
func NewSM3IDHasher() hash.Hash {
	return &IDHasher{inner: sm3.New()}
}

func (h *IDHasher) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	if h.index < 65 {
		if len(p) >= int(65-h.index) {
			copy(h.sm2PkBuf[h.index:], p[:65-h.index])
			if h.sm2PkBuf[0] != 0x04 {
				return 0, errPrefix
			}
			tmp := sm3.NewWithID()
			_, _ = tmp.Write(h.sm2PkBuf[1:])
			copy(h.init[:], tmp.Sum(nil))
			h.inner.Reset()
			_, _ = h.inner.Write(h.init[:])
			_, _ = h.inner.Write(p[65-h.index:])
			h.index = 65
			return 0, nil
		}
		copy(h.sm2PkBuf[h.index:h.index+uint8(len(p))], p[:])
		if h.sm2PkBuf[0] != 0x04 {
			return 0, errPrefix
		}
		h.index += uint8(len(p))
		return 0, nil
	}
	return h.inner.Write(p)
}

//Sum hash sum
func (h *IDHasher) Sum(b []byte) []byte {
	return h.inner.Sum(b)
}

//Reset hash reset
func (h *IDHasher) Reset() {
	h.inner.Reset()
	h.index = 0
}

//Size hash size
func (h *IDHasher) Size() int {
	return h.inner.Size()
}

//BlockSize hash block size
func (h *IDHasher) BlockSize() int {
	return h.inner.BlockSize()
}

//Hash compute hash
func (h *IDHasher) Hash(msg []byte) (hash []byte, err error) {
	h.cleanIfDirty()
	h.dirty = true
	if _, err := h.Write(msg); err != nil {
		return nil, err
	}
	return h.inner.Sum(nil), nil
}

//BatchHash hash with two-dimensional array
func (h *IDHasher) BatchHash(msg [][]byte) (hash []byte, err error) {
	h.cleanIfDirty()
	h.dirty = true
	for i := range msg {
		_, err := h.Write(msg[i])
		if err != nil {
			return nil, err
		}
	}
	return h.inner.Sum(nil), nil
}

func (h *IDHasher) cleanIfDirty() {
	if h.dirty {
		h.inner.Reset()
	}
}
