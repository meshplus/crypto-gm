package sm3

import (
	"encoding/binary"
	"hash"
)

const (
	blockSize = 64
	sumSize   = 32
)

//SM3 to hash msg
type SM3 struct {
	digest    [8]uint32 // digest represents the partial evaluation of V
	length    uint64    // length of the message
	unhandled []byte    // uint8
}

func (sm3 *SM3) pad() []byte {
	msg := make([]byte, len(sm3.unhandled), 128)
	copy(msg, sm3.unhandled[:])
	msg = append(msg, 0x80) // append bit '1'

	for len(msg)%blockSize != 56 {
		msg = append(msg, 0x00)
	}
	// append message length
	msg = append(msg, uint8(sm3.length>>56&0xff))
	msg = append(msg, uint8(sm3.length>>48&0xff))
	msg = append(msg, uint8(sm3.length>>40&0xff))
	msg = append(msg, uint8(sm3.length>>32&0xff))
	msg = append(msg, uint8(sm3.length>>24&0xff))
	msg = append(msg, uint8(sm3.length>>16&0xff))
	msg = append(msg, uint8(sm3.length>>8&0xff))
	msg = append(msg, uint8(sm3.length>>0&0xff))
	if len(msg)%64 != 0 {
		panic("error msgLen")
	}
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
	sm3.unhandled = []byte{}
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
	length := len(p) + len(sm3.unhandled)
	if length < 64 {
		sm3.unhandled = append(sm3.unhandled, p...)
		return toWrite, nil
	}

	nBlocks := length >> 6
	rest := len(sm3.unhandled) % 4
	if rest != 0 && len(p) >= (4-rest) {
		sm3.unhandled = append(sm3.unhandled[:], p[:4-rest]...)
		update(&sm3.digest, sm3.unhandled, p[4-rest:])

	} else {
		//fmt.Println("update 2", &sm3.unhandled[0], &p[0])
		update(&sm3.digest, sm3.unhandled, p)
	}

	// Update unhandled
	sm3.unhandled = p[len(p)-(length-(nBlocks<<6)):]
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
	sm3.unhandled = []byte{
		0x21, 0x53, 0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A,
		0x47, 0x40, 0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39,
		0xF0, 0xA0,
	}
}

// Sum appends the current hash to in and returns the resulting slice. if cap(in) -len(in) >= 32,
//otherwise the it will not change ,and you can get hash from return value
func (sm3 *SM3) Sum(in []byte) []byte {

	msg := sm3.pad()

	// final
	update(&sm3.digest, msg, []byte{})

	// save hash to in
	needed := sm3.Size()
	if cap(in)-len(in) < needed {
		in = make([]byte, needed)
	} else {
		in = in[len(in) : len(in)+needed]
	}

	for i := 0; i < 8; i++ {
		binary.BigEndian.PutUint32(in[i*4:], sm3.digest[i])
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
