package sm2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"encoding/hex"
	"github.com/meshplus/crypto-gm/internal/sm3"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

const msg = `Qulian Technology is an international leading blockchain team with all core team members graduated from Zhejiang University, Tsinghua University and other first-class universities at home and abroad, and Academician Chen Chun of the Chinese Academy of Engineering acted as chairman of the board. The company has a team of nearly 200 people, 90% of whom are technicians, more than 10 have doctoral degrees and 140 have master's degrees. The core competitiveness of the company is Hyperchain bottom technology platform. This platform ranks first in the technical evaluation of several large and medium-sized financial institutions. It is also the first batch of bottom platforms to pass the Blockchain Standard Test of the China Electronics Standardization Institute (CESI) and China Academy of Information and Communications Technology (CAICT) of Ministry of Industry and Information Technology (MIIT). It has applied for 28 patents in blockchain related fields.`

func TestSign(t *testing.T) {
	Key, _ := hex.DecodeString("6332a6b9f834f5c25df0555ff84b2c0cd278f42457bb95534faa4bae0608f537")
	X, _ := hex.DecodeString("86d3205ed0c3db8ef35a74b6bf924cbef75988e835f65f422884e3b1c8cdbde1")
	Y, _ := hex.DecodeString("ea7eee5e7ff177622c3081aea9375d3cfec41867298261aae8f8e1434c9e81f0")
	h := sm3.SignHashSM3(X, Y, []byte(msg))
	sig2, _, err := Sign(h, rand.Reader, Key)
	assert.Nil(t, err)
	b, err := VerifySignature(sig2, h, X, Y)
	assert.Nil(t, err)
	assert.True(t, b)
}
func TestVerifySignature(t *testing.T) {
	Key, _ := hex.DecodeString("6332a6b9f834f5c25df0555ff84b2c0cd278f42457bb95534faa4bae0608f537")
	X, _ := hex.DecodeString("86d3205ed0c3db8ef35a74b6bf924cbef75988e835f65f422884e3b1c8cdbde1")
	Y, _ := hex.DecodeString("ea7eee5e7ff177622c3081aea9375d3cfec41867298261aae8f8e1434c9e81f0")
	h := sm3.SignHashSM3(X, Y, []byte(msg))
	sig1, _, err := Sign(h, rand.Reader, Key)
	assert.Nil(t, err)
	b, err := VerifySignature(sig1, h, X, Y)
	assert.Nil(t, err)
	assert.True(t, b)
}
func BenchmarkSign(b *testing.B) {
	Key, _ := hex.DecodeString("6332a6b9f834f5c25df0555ff84b2c0cd278f42457bb95534faa4bae0608f537")
	X, _ := hex.DecodeString("86d3205ed0c3db8ef35a74b6bf924cbef75988e835f65f422884e3b1c8cdbde1")
	Y, _ := hex.DecodeString("ea7eee5e7ff177622c3081aea9375d3cfec41867298261aae8f8e1434c9e81f0")
	h := sm3.SignHashSM3(X, Y, []byte(msg))
	for i := 0; i < b.N; i++ {
		Sign(h, rand.Reader, Key)
	}
} // 28470 ns

func BenchmarkVerifyP256(b *testing.B) {
	p256 := elliptic.P256()
	hashed := []byte("testing")
	priv, _ := ecdsa.GenerateKey(p256, rand.Reader)
	r, s, _ := ecdsa.Sign(rand.Reader, priv, hashed)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ecdsa.Verify(&priv.PublicKey, hashed, r, s)
	}
} //80690

func TestMarshal(t *testing.T) {
	type signStructT struct {
		R *big.Int
		S *big.Int
	}
	for i := 0; i < 0xfff; i++ {
		r, _ := rand.Int(rand.Reader, Sm2().Params().N)
		s, _ := rand.Int(rand.Reader, Sm2().Params().N)
		var sig signStructT
		sig.R = r
		sig.S = s
		b1, _ := asn1.Marshal(sig)
		b2 := MarshalSig(r.Bytes(), s.Bytes())
		assert.Equal(t, b1, b2)
		asn1.Unmarshal(b1, &sig)
		x, y := Unmarshal(b2)
		assert.Equal(t, sig.R.Bytes(), x)
		assert.Equal(t, sig.S.Bytes(), y)
	}
}
