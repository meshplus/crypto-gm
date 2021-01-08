package gm

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"github.com/meshplus/crypto-gm/internal/sm2"
	"github.com/meshplus/crypto-gm/internal/sm3"
	"io"
	"math/big"
)

const sm2KeyLen = 32

//GM/TO003.5-— 2012
var (
	a       = []byte{0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc}
	h       = big.NewInt(1)
	tmp, _  = new(big.Int).SetString("80000000000000000000000000000000", 16)
	tmp1, _ = new(big.Int).SetString("7fffffffffffffffffffffffffffffff", 16)
	zeroKey = [sm2KeyLen]byte{}
)

//GetSm2Curve get sm2 Curve
func GetSm2Curve() elliptic.Curve {
	return sm2.Sm2()
}

//GenerateSM2Key generate a pair of key,input is algorithm type
func GenerateSM2Key() (*SM2PrivateKey, error) {
	r := new(SM2PrivateKey)
	r.PublicKey.Curve = sm2.Sm2()
	tmp, err := ecdsa.GenerateKey(sm2.Sm2(), rand.Reader)
	if err != nil {
		return r, err
	}
	aa, b, c := tmp.D.Bytes(), tmp.X.Bytes(), tmp.Y.Bytes()
	copy(r.K[32-len(aa):], aa)
	copy(r.PublicKey.X[32-len(b):], b)
	copy(r.PublicKey.Y[32-len(c):], c)
	return r, nil
}

//GenerateSM2KeyForDH generate a key using sm2 for dh
//idA is the ID of self, idB is the ID of another part, isInit indicates whether it is the initiator or not
func GenerateSM2KeyForDH(idA, idB, randA []byte, privateKey, publicAX, publicAY, publicBX, publicBY *big.Int, RB *SM2PublicKey, isInit bool) (*big.Int, *big.Int, []byte, error) {
	curve := sm2.Sm2()

	RAX, _ := curve.ScalarBaseMult(randA)
	//x1 = (2^w + (rax & (2^w -1)))
	x1 := new(big.Int).Add(tmp, new(big.Int).And(RAX, tmp1))
	//ta = (da + x1 * randA)
	x1.Mul(x1, new(big.Int).SetBytes(randA))
	x1.Mod(x1, curve.Params().N)
	tA := new(big.Int).Add(privateKey, x1)
	tA.Mod(tA, curve.Params().N)
	RBX := new(big.Int).SetBytes(RB.X[:])
	RBY := new(big.Int).SetBytes(RB.Y[:])
	//x2 = (2^w + (rbx & (2^w -1)))
	x2 := new(big.Int).Add(tmp, new(big.Int).And(RBX, tmp1))
	if exist := curve.IsOnCurve(RBX, RBY); !exist {
		return nil, nil, nil, errors.New("RB is not on the sm2 curve")
	}
	//x, y = (h*ta)*(pb + (x2 * RB))
	x, y := curve.ScalarMult(RBX, RBY, x2.Bytes())
	x, y = curve.Add(x, y, publicBX, publicBY)
	x, y = curve.ScalarMult(x, y, new(big.Int).Mul(h, tA).Bytes())
	lenID := intToBytes(len(idA) * 8)[2:]
	za := bytes.Join([][]byte{lenID, idA, a, curve.Params().B.Bytes(), curve.Params().Gx.Bytes(), curve.Params().Gy.Bytes(), publicAX.Bytes(), publicAY.Bytes()}, nil)
	lenID = intToBytes(len(idB) * 8)[2:]
	zb := bytes.Join([][]byte{lenID, idB, a, curve.Params().B.Bytes(), curve.Params().Gx.Bytes(), curve.Params().Gy.Bytes(), publicBX.Bytes(), publicBY.Bytes()}, nil)
	zaHash := sm3.Hash(za)
	zbHash := sm3.Hash(zb)
	z := x.Bytes()

	if isInit {
		z = bytes.Join([][]byte{z, y.Bytes(), zaHash[:], zbHash[:]}, nil)
	} else {
		z = bytes.Join([][]byte{z, y.Bytes(), zbHash[:], zaHash[:]}, nil)
	}

	return x, y, z, nil

}

//SM2PrivateKey SM2 private key.
// never new(SM2PrivateKey), use NewSM2PrivateKey()
type SM2PrivateKey struct {
	K         [sm2KeyLen]byte
	PublicKey SM2PublicKey
}

//Bytes return key bytes. Inverse method of FromBytes(K []byte, opt AlgorithmOption)
func (key *SM2PrivateKey) Bytes() ([]byte, error) {
	if key.K == zeroKey {
		return nil, errors.New("SM2PrivateKey.K is nil")
	}
	r := make([]byte, sm2KeyLen)
	copy(r[:], key.K[:])
	return r, nil
}

//FromBytes parse a private Key from bytes, Inverse method of Bytes()
func (key *SM2PrivateKey) FromBytes(k []byte) *SM2PrivateKey {
	if len(k) == 0 || len(k) > 32 {
		return nil
	}
	copy(key.K[sm2KeyLen-len(k):], k)
	return key
}

//SetPublicKey Set the public key contained in the private key
// when get a SM2PrivateKey by FromBytes(...), the public key contained is empty,
// you should invoke SetPublicKey(...) or CalculatePublicKey().
// If you have the Public Key,SetPublicKey(...) is better and faster, since CalculatePublicKey() while calculate public key once again.
func (key *SM2PrivateKey) SetPublicKey(k *SM2PublicKey) *SM2PrivateKey {
	key.PublicKey.X = k.X
	key.PublicKey.Y = k.Y
	key.PublicKey.Curve = sm2.Sm2()
	return key
}

//CalculatePublicKey Calculate the public key contained in the private key
// when get a SM2PrivateKey by FromBytes(...), the public key contained is empty,
// you should invoke SetPublicKey(...) or CalculatePublicKey().
// If you have the Public Key,SetPublicKey(...) is better and faster, since CalculatePublicKey() while calculate public key once again.
func (key *SM2PrivateKey) CalculatePublicKey() *SM2PrivateKey {
	X, Y := sm2.Sm2().ScalarBaseMult(key.K[:])
	copy(key.PublicKey.X[sm2KeyLen-len(X.Bytes()):], X.Bytes())
	copy(key.PublicKey.Y[sm2KeyLen-len(Y.Bytes()):], Y.Bytes())
	return key
}

//Symmetric SM2 is a kind of asymmetric algorithm，so this method always return false.
func (key *SM2PrivateKey) Symmetric() bool {
	return false
}

//Private SM2PrivateKey represent private key of SM2, so this method always return true.
func (key *SM2PrivateKey) Private() bool {
	return true
}

//Public Get SM2PublicKey from a SM2PrivateKey, if SM2PublicKey is empty, this method will invoke CalculatePublicKey().
func (key *SM2PrivateKey) Public() crypto.PublicKey {
	if key.PublicKey.X == zeroKey || key.PublicKey.Y == zeroKey {
		key.CalculatePublicKey()
	}
	return &key.PublicKey
}

//Sign get signature of specific digest by SM2PrivateKey self,so the first parameter will be ignored
func (key *SM2PrivateKey) Sign(reader io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	sign, _, err := sm2.Sign(digest, reader, key.K[:])
	return sign, err
}

//SignBatch get signature of specific digest by SM2PrivateKey self,so the first parameter will be ignored
//first bytes is flag
func (key *SM2PrivateKey) SignBatch(reader io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	sign, flag, err := sm2.Sign(digest, reader, key.K[:])
	ret := make([]byte, len(sign)+1)
	ret[0] = flag
	copy(ret[1:], sign)
	return ret, err
}

//SM2PublicKey SM2 public key.
// never new(SM2PublicKey), use NewSM2PublicKey()
type SM2PublicKey struct {
	Curve elliptic.Curve
	X     [sm2KeyLen]byte
	Y     [sm2KeyLen]byte
}

//FromBytes Parse a public key from 65 bytes and specific algorithm.The reverse method of Bytes()
func (key *SM2PublicKey) FromBytes(k []byte) *SM2PublicKey {
	if len(k) != 65 {
		return nil
	}
	//check is on Curve
	x, y := new(big.Int).SetBytes(k[1:33]), new(big.Int).SetBytes(k[33:])
	if !sm2.Sm2().IsOnCurve(x, y) {
		return nil
	}

	copy(key.X[:], k[1:33])
	copy(key.Y[:], k[33:])
	key.Curve = sm2.Sm2()

	return key
}

//Bytes return key bytes
func (key *SM2PublicKey) Bytes() ([]byte, error) {

	r := make([]byte, 65)
	r[0] = 0x04 // uncompressed point
	copy(r[1:33], key.X[:])
	copy(r[33:65], key.Y[:])
	return r, nil
}

//Symmetric SM2 is a kind of asymmetric algorithm，so this method always return false.
func (key *SM2PublicKey) Symmetric() bool {
	return false
}

//Private SM2PublicKey represent public key of SM2, so this method always return false.
func (key *SM2PublicKey) Private() bool {
	return false
}

//PublicKey return pointer to self
func (key *SM2PublicKey) PublicKey() (*SM2PublicKey, error) {
	return key, nil
}
