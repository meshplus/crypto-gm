package gm

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/meshplus/crypto-gm/internal/sm3"
	"github.com/stretchr/testify/assert"
	"os"
	"os/exec"
	"testing"
)

func TestNewSM3Hasher(t *testing.T) {
	msg := bytes.Repeat([]byte("abcd"), 16)
	//see http://www.sca.gov.cn/sca/xwdt/2010-12/17/1002389/files/302a3ada057c4a73830536d03e683110.pdf
	target := "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"
	sm3 := NewSM3Hasher()
	h, err := sm3.Hash([]byte(msg))
	assert.Nil(t, err)
	assert.Equal(t, target, hex.EncodeToString(h))
}

func TestNewSM3Hasher2(t *testing.T) {
	msg := "abc"
	//see http://www.sca.gov.cn/sca/xwdt/2010-12/17/1002389/files/302a3ada057c4a73830536d03e683110.pdf
	target := "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
	sm3 := NewSM3Hasher()
	h, err := sm3.Hash([]byte(msg))
	assert.Nil(t, err)
	assert.Equal(t, target, hex.EncodeToString(h))
}
func TestHashBeforeSM2(t *testing.T) {
	type args struct {
		key  string
		hash string
	}
	tests := []args{
		{key: "36b21abb731ecf12f36f2f28145c053062f096cf30d49c2fc6ffc4a5d901a0fd", hash: "99cc9df3e4a00d78d188526bdbd31bb37dd565e11b9c3d0c995775d72768ac0b"},
		{key: "533223b91b530c253eaa035603e7987b935425921a34767777c6c2cd477a0593", hash: "91cce5c386b55b658b875b53256b915341c373bce5b74498229625687edf96d3"},
		{key: "177c62b958177d84a5b6b7e0e64f77b5d2d971c125b95e1c43120178cf8508f3", hash: "3109cb5029c607a5bd3eef78b41fffd8a59c2f223f470593d095dbf401d199d7"},
		{key: "53d7f3af7009d492438279af5ce037fad55f040f6e2c29ffc90d0ccbcf30c5cb", hash: "9b9608aafbbd27a59913f85d3f5d445bfaadeb52c42a99c410c7c3a260038653"},
		{key: "9cb897d330a39105ddc0703f382f550f04bdffcd4cc082a5beaf5ee4adde2398", hash: "43eead62f193a402bcf4a1258949516da4d17f47b99777cdd391c5e0cd55fd98"},
		{key: "8286d5706058cdc037108419ce165e0f7082868c2984c0ec673173b155cb3e8a", hash: "013824ad5537f61be4c1a87483deedbd5a33eb835caa1117bba7217a2df3fbd7"},
		{key: "9ab086e95ca44c9b580e45f4247f81f04f695094edc2f3b660155b00bd4222e6", hash: "9fb32a37d920e667c4c5a826a11d7ef1312e230e84901d819297f50630af8cb1"},
		{key: "3fdc380fba2fe1561899536b619a559399725b14eb12c465364ddd383a61f01f", hash: "a1906ebc990c57d8f6c0dbaa09df1eed7569c2b92cb06982c20cc9091efd42d4"},
		{key: "f44f83f44cfcf3779886ad7be648c39bec010dcb336f66d51836f0e1441f25f8", hash: "b6e96cfac4899c7a00872a1240215aa85f7ac352247363b6e8679686d86c8874"},
		{key: "9aa8a006d96f4dda9dfd695a01b473e1681fad1ab96b6c390c2cda400efbf9c5", hash: "53aa8c2e6a7cdd4d9e308058fbd1ea66fcaaeac0cae85f029346d266aa24da83"},
	}

	for _, tt := range tests {
		t.Run("sm2Sign", func(t *testing.T) {
			key := new(SM2PrivateKey)
			keyByte, err := hex.DecodeString(tt.key)
			assert.Nil(t, err)
			key.FromBytes(keyByte)
			key.CalculatePublicKey()
			hash := HashBeforeSM2(&key.PublicKey, []byte(msg))
			assert.Equal(t, hex.EncodeToString(hash), tt.hash)
		})
	}
}
func TestHasher_BatchHash(t *testing.T) {
	msg1 := bytes.Repeat([]byte("abcd"), 7)
	msg2 := bytes.Repeat([]byte("abcd"), 9)
	target := "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"
	sm3 := NewSM3Hasher()
	h, err := sm3.BatchHash([][]byte{msg1, msg2})
	assert.Nil(t, err)
	assert.Equal(t, target, hex.EncodeToString(h))
}

func BenchmarkNewSM3Hasher(b *testing.B) {
	msg := make([]byte, 1024)
	_, _ = rand.Read(msg)
	sm3 := NewSM3Hasher()

	for i := 0; i < b.N; i++ {
		b.StartTimer()
		h, err := sm3.Hash([]byte(msg))
		b.StopTimer()
		sm3.cleanIfDirty()
		assert.Nil(b, err)
		assert.Equal(b, 32, len(h))
	}
}

func TestGetSM3Hasher(t *testing.T) {
	h := GetSM3Hasher()
	assert.Equal(t, h.Size(), 32)
}

func creatFile() error {
	_, err := os.Create("./in")
	if err != nil {
		return err
	}
	_, err = os.Create("./out")
	return err
}
func removeFile() {
	defer func() {
		_ = os.Remove("./in")
		_ = os.Remove("./out")
	}()
}
func TestSM3Hash(t *testing.T) {
	type args struct {
		msg string
	}
	tests := []struct {
		name     string
		args     args
		wantHash string
	}{
		{"sm3TestCase1",
			args{"5D4A5E75727A58622633302162663D31534750242775214A646B7328425B4770"},
			"30703d104c2b2035f23bf4b1f1d4a2f84774f01fecfd8797d377e78a9ac4670a"},
		{"sm3TestCase2",
			args{"34"},
			"9b602e9b9e8556eff1a28962d4580b34d9bf054f4831f4f924d4a6dfad660e88"},
		{"sm3TestCase3",
			args{"3D5B78505C6264297654255B7731685C534B6949766C696B73464C3348586230B6741265B6A2B737664275841546628655A6F00383D375B553452264067C026CFBD1"},
			"d0c8fb45694749e42e51b6fadf04125f66d5c4d2da19c098ba7fad3baf9a3fb8"},
		{"sm3TestCase4",
			args{"4F792321483855244E4C496877497745"},
			"0329d664aeb2d4178cd210c61df7debe57bd904f9551203c547e21dd1fce71b5"},
		{"sm3TestCase5",
			args{"48227233767B4C6D2B755D55444024776A4867285C3930296B256F53485B4044"},
			"32d0591759269a65189127481b063a5efee14adec6c2dc4d0432c53432062513"},
	}
	err := creatFile()
	if err != nil {
		fmt.Println("can not creat file")
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, _ := hex.DecodeString(tt.args.msg)
			gotHash := sm3.Hash(msg)
			if hex.EncodeToString(gotHash) != tt.wantHash {
				t.Errorf("Hash() gotHash = %s, want %s", hex.EncodeToString(gotHash), tt.wantHash)
			}
			fmt.Println("hash :", hex.EncodeToString(gotHash))
			//compare result in openssl
			file, err := os.OpenFile("./in", os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0644)
			if err != nil {
				t.Errorf("can not open file")
			}
			_, err = file.Write(msg)
			if err != nil {
				t.Errorf("can not write msg")
			}
			cmd := exec.Command("/bin/sh", "-c", "openssl dgst -sm3  -out ./out ./in ")
			_, err = cmd.Output()
			if err != nil {
				fmt.Println("err:", err)
				return
			}
			file, err = os.OpenFile("./out", os.O_CREATE|os.O_APPEND|os.O_RDWR, 0644)
			if err != nil {
				fmt.Println("can not open file", err)
				return
			}
			newdst := make([]byte, 76)
			_, err = file.Read(newdst)
			if err != nil {
				fmt.Println("err:", err)
				return
			}
			assert.Equal(t, string(newdst[11:75]), hex.EncodeToString(gotHash))
			if string(newdst[11:75]) != hex.EncodeToString(gotHash) {
				t.Errorf("different result with openssl, openssl = %v, got=%s", string(newdst[11:]), hex.EncodeToString(gotHash))
			}
		})
	}
	removeFile()
}
