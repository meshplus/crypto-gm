package gm

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"testing"
)

var (
	pubKey     = "04F4CD1B71C44E01AEEF89BA84B70F168718E87ADA4BDA50D418678D8412C41B0AD869D8304C8F2DB925E631C8628C0E15044BDCC86084888CBA56A5A22B3A42CD"
	privateKey = "9DC7D7BBBC600AFB122A63A22BA3BD5187231BD49574BBFA018B2F6424CCBCE3"
)
var message = []byte("One ping only, please.One ping only, please.One ping only, please.One ping only, please.One ping only, please.")

func TestCrypt(t *testing.T) {
	var err error
	vk, _ := hex.DecodeString(privateKey)
	pk, _ := hex.DecodeString(pubKey)
	testKey := new(SM2PrivateKey).FromBytes(vk)
	testPubKey := new(SM2PublicKey).FromBytes(pk)

	out, err := Encrypt(testPubKey, message, rand.Reader)
	if err != nil {
		t.Fatalf("%v", err)
	}

	out, err = Decrypt(testKey, out)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if !bytes.Equal(out, message) {
		t.Fatal("Decryption return different plaintext than original message.")
	}
}

const cipherText = `0409332fadf1804bb892d3d5851dd2414eb0f8363ae79688c0afd23581faa0c05008b96c328daeafc8c8b428f7543ba6c6fe7176342f68b6830b98afc04b050d928c755e4d4a43bf292437db94724b81d886479ffdbc1ca18debbef8450c4ad38b8f210d9db207a158d5d0d1e01369506fe592e77578b3dff7df7f7de78e278b7f2074f01e`

func TestDecrypt(t *testing.T) {
	c, _ := hex.DecodeString(cipherText)
	vk, _ := hex.DecodeString(privateKey)
	testKey := new(SM2PrivateKey).FromBytes(vk)
	out, err := Decrypt(testKey, c)
	assert.Nil(t, err)
	assert.Equal(t, string(out), "123456789012345678901234567890123456")
}
