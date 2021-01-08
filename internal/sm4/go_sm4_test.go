package sm4

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"github.com/stretchr/testify/assert"
	"os"
	"reflect"
	"testing"
)

const msg = `Qulian Technology is an international leading blockchain team with all core team members graduated from Zhejiang University, Tsinghua University and other first-class universities at home and abroad, and Academician Chen Chun of the Chinese Academy of Engineering acted as chairman of the board. The company has a team of nearly 200 people, 90% of whom are technicians, more than 10 have doctoral degrees and 140 have master's degrees. The core competitiveness of the company is Hyperchain bottom technology platform. This platform ranks first in the technical evaluation of several large and medium-sized financial institutions. It is also the first batch of bottom platforms to pass the Blockchain Standard Test of the China Electronics Standardization Institute (CESI) and China Academy of Information and Communications Technology (CAICT) of Ministry of Industry and Information Technology (MIIT). It has applied for 28 patents in blockchain related fields.`

func TestSM4(t *testing.T) {
	key := []byte("1234567890abcdef")
	fmt.Printf("key = %v\n", key)
	data := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	ok, err := WriteKeyToPem("key.pem", key, nil)
	assert.True(t, ok)
	assert.Nil(t, err)
	ok, err = WriteKeyToPem("key.pem", key, []byte("123456"))
	assert.True(t, ok)
	assert.Nil(t, err)
	_, err = WriteKeytoMem(key, nil)
	assert.Nil(t, err)
	_, err = WriteKeytoMem(key, []byte("123456"))
	assert.Nil(t, err)
	_, err = ReadKeyFromPem("key.pem", nil)
	assert.NotNil(t, err)
	key, err = ReadKeyFromPem("key.pem", []byte("123456"))
	fmt.Printf("key = %v\n", key)
	assert.Nil(t, err)
	fmt.Printf("data = %x\n", data)
	c, err := NewCipher(key)
	assert.Nil(t, err)
	d0 := make([]byte, 16)
	c.Encrypt(d0, data)
	fmt.Printf("d0 = %x\n", d0)
	d1 := make([]byte, 16)
	c.Decrypt(d1, d0)
	fmt.Printf("d1 = %x\n", d1)
	if sa := testCompare(data, d1); sa != true {
		fmt.Printf("Error data!")
	}
	_ = os.Remove("key.pem")

}

func BenchmarkSM4(t *testing.B) {
	t.ReportAllocs()
	key := []byte("1234567890abcdef")
	data := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	c, err := NewCipher(key)
	assert.Nil(t, err)

	for i := 0; i < t.N; i++ {
		d0 := make([]byte, 16)
		c.Encrypt(d0, data)
		d1 := make([]byte, 16)
		c.Decrypt(d1, d0)
	}
}

func TestErrKeyLen(t *testing.T) {
	key := []byte("1234567890abcdefg")
	_, err := NewCipher(key)
	assert.NotNil(t, err)
	key = []byte("1234")
	_, err = NewCipher(key)
	assert.NotNil(t, err)
}

func testCompare(key1, key2 []byte) bool {
	if len(key1) != len(key2) {
		return false
	}
	for i, v := range key1 {
		if i == 1 {
			fmt.Println("type of v", reflect.TypeOf(v))
		}
		a := key2[i]
		if a != v {
			return false
		}
	}
	return true
}

func TestGmSM4(t *testing.T) {
	key := make([]byte, 16)
	_, _ = rand.Read(key)
	padding := 16 - len([]byte(msg))%16
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	text := append([]byte(msg), padtext...)
	iv := make([]byte, 16)
	_, _ = rand.Read(iv)
	encryptedMsg, err := Sm4EncCBCIV(SM4Key(key), iv, text)
	assert.Nil(t, err)
	encrypted := append(iv, encryptedMsg...)
	en := make([]byte, len(encrypted)-16)
	copy(iv, encrypted[0:16])
	copy(en, encrypted[16:])
	text, err = Sm4DecCBCIV(SM4Key(key), iv, en)
	assert.Nil(t, err)
	length := len(text)
	unpadding := int(text[length-1])
	if unpadding > length {
		t.Fatal(err)
	}
	text = text[:(length - unpadding)]
	assert.Equal(t, text, []byte(msg))
}

func TestEncryptDecryptBlock(t *testing.T) {
	key := make([]byte, 16)
	_, _ = rand.Read(key)
	encrypted := make([]byte, 16)
	plaintext := make([]byte, 16)
	decrypted := make([]byte, 16)
	_, _ = rand.Read(plaintext)
	EncryptBlock(SM4Key(key), encrypted, plaintext)
	DecryptBlock(SM4Key(key), decrypted, encrypted)
	assert.Equal(t, plaintext, decrypted)
}
