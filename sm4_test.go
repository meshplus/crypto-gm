package gm

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/stretchr/testify/assert"
	"os"
	"os/exec"
	"reflect"
	"testing"
)

func TestSM4(t *testing.T) {
	sm4 := new(SM4)
	key := make([]byte, 16)
	_, _ = rand.Read(key)
	c, err := sm4.Encrypt(SM4Key(key), []byte(msg), rand.Reader)
	assert.Nil(t, err)
	o, err := sm4.Decrypt(SM4Key(key), c)
	assert.Nil(t, err)
	assert.Equal(t, o, []byte(msg))

	newKey := SM4Key(key)
	newKey.FromBytes(key, nil)
	sm4Key, err := newKey.Bytes()
	assert.Nil(t, err)
	assert.Equal(t, sm4Key, key)
}

func BenchmarkSM4_Encrypt(b *testing.B) {
	key := []byte("1234567890abcdef")
	data := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	_, _ = rand.Read(key)
	sm4 := SM4{}
	for i := 0; i < b.N; i++ {
		c, err := sm4.Encrypt(SM4Key(key), data, rand.Reader)
		assert.Nil(b, err)
		o, err := sm4.Decrypt(SM4Key(key), c)
		assert.Nil(b, err)
		assert.Equal(b, o, data)
	}
}

func BenchmarkSM4_Decrypt(b *testing.B) {
	msg := make([]byte, 1024)
	_, _ = rand.Read(msg)
	sm4 := new(SM4)
	key := make([]byte, 16)
	_, _ = rand.Read(key)
	for i := 0; i < b.N; i++ {
		c, err := sm4.Encrypt(SM4Key(key), []byte(msg), rand.Reader)
		assert.Nil(b, err)
		b.StartTimer()
		o, err := sm4.Decrypt(SM4Key(key), c)
		b.StopTimer()
		assert.Nil(b, err)
		assert.Equal(b, o, []byte(msg))
	}
}

func TestGetSm4Cipher(t *testing.T) {
	cb, err := GetSm4Cipher([]byte("1234567812345678"))
	assert.Nil(t, err)
	assert.Equal(t, cb.BlockSize(), 16)
	pt := []byte{1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4}
	cb.Encrypt(pt, pt)
	assert.NotEqual(t, pt, []byte{1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4})
	cb.Decrypt(pt, pt)
	assert.Equal(t, pt, []byte{1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4})
}

func TestSm4EncryptCBCIV(t *testing.T) {
	type args struct {
		key string
		iv  string
		src string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"sm4EncCBC1",
			args{"372463645A5D3930302373755F5F6479",
				"3074674B2B7025524C46654F43225E31",
				"5D25345F494A725E5044575473626F6A"},
			"3074674b2b7025524c46654f43225e314bd2fe0bdef4cb1bf49461071d5cf68c3b2a483c674e6838656dc6b87469581f",
			false},
		{"sm4EncCBC2",
			args{"4D422D466C6330354B4E68397431395D",
				"73674E7678674E6139452A566E286244",
				"46415C365B6741265B6A2B737664275841546628655A6F00383D375B553452264067C026CFBD1D5CAFD1B91DDB35A85C"},
			"73674e7678674e6139452a566e2862444067c026cfbd1d5cafd1b91ddb35a85cfc03a64031e3735141b" +
				"8c29856a76eaf09b772c0dfbc82aeb427f292cf873a35c26efe5baecfa7aa15875ae7e2d9811f",
			false},
		{"sm4EncCBC3",
			args{"7135422763566253415E7B35587A6350",
				"2D40455F752463697B4A725A46296578",
				"4C2B66654B70632744216E757A"},
			"2d40455f752463697b4a725a462965787753b46d4e3af9b65ef98978262b4a8f",
			false},
		{"sm4EncCBC4",
			args{"4A637550533D443379592A755E653950",
				"664574536B665F422B252736455F3D41",
				"4E4563283636774C5C5D7D266F27632A452A4C5750442656613549725F573650"},
			"664574536b665f422b252736455f3d4194aca917938f3406b5f438c36fb0e4354b1d2b27cd32b569ce141bf75339854b79d3b8c40a794bb43d76b96f048cc72e", false},
		{"sm4EncCBC5",
			args{"577665236145575F32283477614E4F2D",
				"41735F403042383D4F71462723495C25",
				"444F3161423D6935653D292A24784A4B725F4A526376216C624F35"},
			"41735f403042383d4f71462723495c25ec38e69aa7e23232e92fd294825abb4387131c2ed9bb84524d33aaecc78b8845",
			false},
	}
	err := creatFile()
	if err != nil {
		fmt.Println("can not creat file")
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, _ := hex.DecodeString(tt.args.key)
			src, _ := hex.DecodeString(tt.args.src)
			iv, _ := hex.DecodeString(tt.args.iv)
			got, err := Sm4EncryptCBC(key, src, bytes.NewReader(iv))
			if (err != nil) != tt.wantErr {
				t.Errorf("Sm4EncCBCIV() error = %v, wantErr= %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(hex.EncodeToString(got), tt.want) {
				t.Errorf("Sm4EncCBCIV() got = %v, want= %v", hex.EncodeToString(got), tt.want)
			}
			fmt.Println("cipher without iv : ", hex.EncodeToString(got[16:]))
			//compare result in openssl
			file, err := os.OpenFile("./in", os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0644)
			if err != nil {
				t.Errorf("can not open file")
			}
			_, err = file.Write(src)
			if err != nil {
				t.Errorf("can not write msg")
			}
			cmd := exec.Command("/bin/sh", "-c", "openssl enc -sm4-cbc -e -K "+tt.args.key+" -iv "+tt.args.iv+" -in ./in -out ./out")
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
			newdst := make([]byte, len(got)-16)
			_, err = file.Read(newdst)
			if err != nil {
				fmt.Println("err:", err)
				return
			}
			if !bytes.Equal(newdst, got[16:]) {
				t.Errorf("different result with openssl, openssl = %s, got=%s", hex.EncodeToString(newdst), hex.EncodeToString(got[16:]))
			}
		})
	}
	removeFile()
}

func TestSm4DecryptCBCIV(t *testing.T) {
	type args struct {
		key string
		iv  string
		src string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"sm4DecCBC1",
			args{"2854217B564D734E41216C307257216B",
				"5C593436727B376C526A636155363334",
				"D3525167F3CA619137169F0F8F5F5B3B"},
			"2b6c",
			false},
		{"sm4DecCBC2",
			args{"39215E5A336B666B633D515667487778",
				"6B725338535B364965594850685D3046",
				"A68BC477CB074A0A3C027A3D81FCC9C1D419787B3A968FA8604EE2A86FFBBCC5"},
			"535d54796376757b56732b736c212533",
			false},
		{"sm4DecCBC3",
			args{"676D7A53247239536772785B41373636",
				"524344524021535E4075254545454562",
				"5836153707980FBA031AF8DEAC75FFE1A9C8FD915AF41DFDABA9E0C726238F28" +
					"1D0CA77E9D322F6F3BD43AA41C07BBA8"},
			"32255e416240357a4467413d785c385c34596f5844737a412440344b65355e49",
			false},
		{"sm4DecCBC4",
			args{"502B2D36496F2D2D754B7929306D296A",
				"4F405E6E325F4031325D4F5521445F4B",
				"D478078C29A9D2C22ECA4E213473EBF85094F42B27D15230DDD909C7A3835ED02F" +
					"BC143E8F77B8B3E0485D5C767BCCF5"},
			"48245039447652667353485867524a574e5276663d6d6b4449654370364b4f6124b38db3" +
				"db4944",
			false},
		{"sm4DecCBC5",
			args{"7D7D375C422978507375346F6C7B4F71",
				"24486A776A68586E3147633330297729",
				"CDC337558ED2337CE139978CB296FF4F68FB8D060DEDF1C280664A5F55FCDB6E3291D" +
					"CFF6EC584BF4254A229D4D2C832BA34B20ADE0D7B395B7733BEC3D2851F"},
			"377542484f4e264f77464c47505353725b38254c7b653078483537407a4b636255fcdb6e567f9d43325dacc1e01bdaa6e73e7363",
			false},
	}
	err := creatFile()
	if err != nil {
		fmt.Println("can not open file")
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, _ := hex.DecodeString(tt.args.key)
			src, _ := hex.DecodeString(tt.args.src)
			iv, _ := hex.DecodeString(tt.args.iv)
			ivsrc := append(iv, src...)
			got, err := Sm4DecryptCBC(key, ivsrc)
			if (err != nil) != tt.wantErr {
				t.Errorf("Sm4EncCBCIV() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			fmt.Println("plaintext:", hex.EncodeToString(got))
			if !reflect.DeepEqual(hex.EncodeToString(got), tt.want) {
				t.Errorf("Sm4EncCBCIV() got = %v, want %v", hex.EncodeToString(got), tt.want)
			}
			//compare result in openssl
			file, err := os.OpenFile("./in", os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0644)
			if err != nil {
				t.Errorf("can not open file")
			}
			_, err = file.Write(src)
			if err != nil {
				t.Errorf("can not write msg")
			}
			cmd := exec.Command("/bin/sh", "-c", "openssl enc -sm4-cbc -d -K "+tt.args.key+" -iv "+tt.args.iv+" -in ./in -out ./out")
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
			newdst := make([]byte, len(got))
			_, err = file.Read(newdst)
			if err != nil {
				fmt.Println("err:", err)
				return
			}
			if !bytes.Equal(newdst, got) {
				t.Errorf("different result with openssl, openssl = %s, got=%s", hex.EncodeToString(newdst), hex.EncodeToString(got[16:]))
			}
		})
	}
	removeFile()
}
