package gm

import (
	"bytes"
	"crypto/cipher"
	"errors"
	"fmt"
	"github.com/meshplus/crypto-gm/internal/sm4"
	"io"
)

//SM4 a tool to encrypt and decrypt
type SM4 struct {
}

//Encrypt encrypt with sm4, use CBC mode with vi
func (ea *SM4) Encrypt(key, originMsg []byte, reader io.Reader) (encryptedMsg []byte, err error) {
	return Sm4EncryptCBC(key, originMsg, reader)
}

//Decrypt decrypt with sm4, use CBC mode with vi
func (ea *SM4) Decrypt(key, encryptedMsg []byte) (originMsg []byte, err error) {
	return Sm4DecryptCBC(key, encryptedMsg)
}

//SM4Key represent sm4 key
type SM4Key []byte

//Bytes return bytes
func (t SM4Key) Bytes() ([]byte, error) {
	r := make([]byte, len(t))
	copy(r, t)
	return r, nil
}

//FromBytes get a key from bytes
func (t SM4Key) FromBytes(k []byte, opt interface{}) []byte {
	copy(t, k)
	return t
}

//Sm4EncryptCBC encrypt with sm4, use CBC mode with iv
//iv is
func Sm4EncryptCBC(key, originMsg []byte, randReader io.Reader) ([]byte, error) {
	msg := pkcs5Padding(originMsg, 16)
	iv := make([]byte, 16)
	_, err := randReader.Read(iv)
	if err != nil {
		return nil, err
	}
	encryptedMsg, err := sm4.Sm4EncCBCIV(key, iv, msg)
	encrypted := append(iv, encryptedMsg...)
	return encrypted, err
}

//Sm4DecryptCBC decrypt with sm4, use CBC mode with iv
func Sm4DecryptCBC(key, src []byte) ([]byte, error) {
	if len(src) < 16 {
		return nil, fmt.Errorf("cipher text is too short")
	}
	iv := make([]byte, 16)
	en := make([]byte, len(src)-16)
	copy(iv, src[0:16])
	copy(en, src[16:])
	msg, _ := sm4.Sm4DecCBCIV(key, iv, en)
	msg, err := pkcs5UnPadding(msg)
	if err != nil {
		return nil, err
	}
	return msg, nil
}

//pkcs5Padding padding with pkcs5
func pkcs5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

//pkcs5UnPadding unpadding with pkcs5
func pkcs5UnPadding(origData []byte) ([]byte, error) {
	length := len(origData)
	unpadding := int(origData[length-1])
	if unpadding > length {
		return nil, errors.New("decrypt failed,please check it")
	}
	return origData[:(length - unpadding)], nil
}

//GetSm4Cipher get cipher.Block
func GetSm4Cipher(key []byte) (cipher.Block, error) {
	return sm4.NewCipher(key)
}
