package sm3

import (
	"encoding/base64"
	"fmt"
	"hash"
)

const (
	blockSize     = 64
	blockSizeMask = 0x3f
	sumSize       = 32
)

//SM3 to hash msg
type SM3 struct {
	unhandledLength int
	digest          [8]uint32       // digest represents the partial evaluation of V
	length          uint64          // length of the message
	unhandled       [blockSize]byte // uint8
}

//Debug printf state of sm3
func (sm3 *SM3) Debug() string {
	return fmt.Sprintf("length:%v, digest: %x,%x,%x,%x,%x,%x,%x,%x\nunhandled:%v", sm3.length,
		sm3.digest[0], sm3.digest[1], sm3.digest[2], sm3.digest[3], sm3.digest[4], sm3.digest[5], sm3.digest[6], sm3.digest[7],
		base64.StdEncoding.EncodeToString(sm3.unhandled[:sm3.unhandledLength]))
}

func (sm3 *SM3) pad(msg []byte) []byte {
	copy(msg, sm3.unhandled[:sm3.unhandledLength])
	msg = append(msg, 0x80) // append bit '1'

	appendlength := 56 - len(msg)&blockSizeMask
	if appendlength < 0 {
		appendlength += blockSize
	}
	msg = msg[:len(msg)+appendlength]

	// append message length
	msg = append(msg, uint8(sm3.length>>56&0xff))
	msg = append(msg, uint8(sm3.length>>48&0xff))
	msg = append(msg, uint8(sm3.length>>40&0xff))
	msg = append(msg, uint8(sm3.length>>32&0xff))
	msg = append(msg, uint8(sm3.length>>24&0xff))
	msg = append(msg, uint8(sm3.length>>16&0xff))
	msg = append(msg, uint8(sm3.length>>8&0xff))
	msg = append(msg, uint8(sm3.length>>0&0xff))
	return msg
}

//New to get a sm3 hash function
func New() hash.Hash {
	var sm3 SM3
	sm3.Reset()
	return &sm3
}

//NewWithID add ID hash
func NewWithID() hash.Hash {
	var sm3 SM3
	sm3.resetWithDefaultID()
	return &sm3
}

//BlockSize required by the hash.Hash interface.BlockSize returns the hash's underlying block size.
func (sm3 *SM3) BlockSize() int { return blockSize }

//Size required by the hash.Hash interface. Size returns the number of bytes Sum will return.
func (sm3 *SM3) Size() int { return sumSize }

//Reset clears the internal state by zeroing bytes in the state buffer. This can be skipped for a newly-created hash state; the default zero-allocated state is correct.
func (sm3 *SM3) Reset() {
	// Reset digest
	sm3.digest[0] = 0x7380166f
	sm3.digest[1] = 0x4914b2b9
	sm3.digest[2] = 0x172442d7
	sm3.digest[3] = 0xda8a0600
	sm3.digest[4] = 0xa96f30bc
	sm3.digest[5] = 0x163138aa
	sm3.digest[6] = 0xe38dee4d
	sm3.digest[7] = 0xb0fb0e4e

	sm3.length = 0
	sm3.unhandledLength = 0
}

//Write required by the hash.Hash interface.
// Write (via the embedded io.Writer interface) adds more data to the running hash.
// It never returns an error.
func (sm3 *SM3) Write(p []byte) (int, error) {

	toWrite := len(p)
	if toWrite == 0 {
		return toWrite, nil
	}
	sm3.length += uint64(len(p) << 3)
	length := len(p) + sm3.unhandledLength
	if length < 64 {
		copy(sm3.unhandled[sm3.unhandledLength:], p)
		sm3.unhandledLength = length
		return toWrite, nil
	}

	nBlocks := length >> 6
	rest := sm3.unhandledLength % 4
	if rest != 0 && len(p) >= (4-rest) {
		copy(sm3.unhandled[sm3.unhandledLength:], p[:4-rest])
		sm3.unhandledLength += 4 - rest
		update(&sm3.digest, sm3.unhandled[:sm3.unhandledLength], p[4-rest:])
	} else {
		update(&sm3.digest, sm3.unhandled[:sm3.unhandledLength], p)
	}

	// Update unhandled
	sm3.unhandledLength = length - (nBlocks << 6)
	unHandleLength := len(p) - sm3.unhandledLength
	copy(sm3.unhandled[:], p[unHandleLength:])
	return toWrite, nil
}

func (sm3 *SM3) resetWithDefaultID() {
	sm3.digest[0] = 0xadadedb5
	sm3.digest[1] = 0x0446043f
	sm3.digest[2] = 0x08a87ace
	sm3.digest[3] = 0xe86d2243
	sm3.digest[4] = 0x8e232383
	sm3.digest[5] = 0xbfc81fe2
	sm3.digest[6] = 0xcf9117c8
	sm3.digest[7] = 0x4707011d
	sm3.length = 1168
	sm3.unhandled = [64]byte{
		0x21, 0x53, 0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A,
		0x47, 0x40, 0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39,
		0xF0, 0xA0,
	}
	sm3.unhandledLength = 18
}

// Sum appends the current hash to in and returns the resulting slice. if cap(in) -len(in) >= 32,
//otherwise the it will not change ,and you can get hash from return value
func (sm3 *SM3) Sum(in []byte) []byte {
	msg := make([]byte, sm3.unhandledLength, 128)
	msg = sm3.pad(msg)

	// final
	update(&sm3.digest, msg, []byte{})

	var ret []byte
	if cap(in)-len(in) < 32 {
		ret = make([]byte, len(in), 32+len(in))
		copy(ret, in)
		in = ret
	}
	for _, v := range sm3.digest {
		in = append(in, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
	return in
}

//Hash return hash of data
func Hash(data []byte) []byte {
	var sm3 SM3
	sm3.Reset()
	_, _ = sm3.Write(data)
	return sm3.Sum(nil)
}

//SignHashSM3 To verify SM2 signatures, digest should be padded by the follow method
// X, Y: the byte form of points X, Y in an SM2 public key
//BenchmarkVerify2-4   	    3000	    405031 ns/op
func SignHashSM3(X, Y []byte, msg []byte) []byte {
	h := NewWithID()
	_, _ = h.Write(X)
	_, _ = h.Write(Y)
	res := h.Sum(nil)
	h.Reset()
	_, _ = h.Write(res)
	_, _ = h.Write(msg)
	return h.Sum(nil)
}
