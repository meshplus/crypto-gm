package gm

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/meshplus/crypto-gm/internal/sm2"
	"github.com/meshplus/crypto-gm/internal/sm3"
	"github.com/stretchr/testify/assert"
	"math/big"
	"strings"
	"testing"
)

const msg = `Qulian Technology is an international leading blockchain team with all core team members graduated from Zhejiang University, Tsinghua University and other first-class universities at home and abroad, and Academician Chen Chun of the Chinese Academy of Engineering acted as chairman of the board. The company has a team of nearly 200 people, 90% of whom are technicians, more than 10 have doctoral degrees and 140 have master's degrees. The core competitiveness of the company is Hyperchain bottom technology platform. This platform ranks first in the technical evaluation of several large and medium-sized financial institutions. It is also the first batch of bottom platforms to pass the Blockchain Standard Test of the China Electronics Standardization Institute (CESI) and China Academy of Information and Communications Technology (CAICT) of Ministry of Industry and Information Technology (MIIT). It has applied for 28 patents in blockchain related fields.`

func TestGenerateSM2Key(t *testing.T) {
	for i := 0; i < 5; i++ {
		key, err := GenerateSM2Key()
		skBytes, _ := key.Bytes()
		fmt.Println("private key:", hex.EncodeToString(skBytes[:]))
		pkBytes, _ := key.PublicKey.Bytes()
		fmt.Println("public key:", hex.EncodeToString(pkBytes[1:]))
		assert.Nil(t, err)
		ok := sm2.Sm2().IsOnCurve(new(big.Int).SetBytes(key.PublicKey.X[:]), new(big.Int).SetBytes(key.PublicKey.Y[:]))
		assert.True(t, ok)
	}
}

func TestGenerateSM2KeyForDH(t *testing.T) {
	privateA, err := GenerateSM2Key()
	assert.Nil(t, err)
	privateB, err := GenerateSM2Key()
	assert.Nil(t, err)
	priv1, err := GenerateSM2Key()
	assert.Nil(t, err)
	randAG := priv1.Public().(*SM2PublicKey)
	randA := priv1.K

	priv2, err := GenerateSM2Key()
	assert.Nil(t, err)
	randBG := priv2.Public().(*SM2PublicKey)
	randB := priv2.K

	publicA := privateA.Public().(*SM2PublicKey)
	publicB := privateB.Public().(*SM2PublicKey)
	idA := intToBytes(1)
	idB := intToBytes(1)
	dA := new(big.Int).SetBytes(privateA.K[:])
	pAX := new(big.Int).SetBytes(publicA.X[:])
	pAY := new(big.Int).SetBytes(publicA.Y[:])
	dB := new(big.Int).SetBytes(privateB.K[:])
	pBX := new(big.Int).SetBytes(publicB.X[:])
	pBY := new(big.Int).SetBytes(publicB.Y[:])
	xA, yA, zA, err := GenerateSM2KeyForDH(idA, idB, randA[:], dA, pAX, pAY, pBX, pBY, randBG, true)
	assert.Nil(t, err)

	xB, yB, zB, err := GenerateSM2KeyForDH(idB, idA, randB[:], dB, pBX, pBY, pAX, pAY, randAG, false)
	assert.EqualValues(t, xA, xB)
	assert.EqualValues(t, yA, yB)
	assert.EqualValues(t, zA, zB)
	assert.Nil(t, err)

}
func TestPrivateKeyBytes(t *testing.T) {
	kvbs, _ := hex.DecodeString("12332132132131321321321300000000123321321321313213213213")
	sk := new(SM2PrivateKey)
	assert.Nil(t, sk.FromBytes(kvbs, 0))
	sk.CalculatePublicKey()

	targetKvbs, _ := sk.Bytes()
	assert.Equal(t, "0000000012332132132131321321321300000000123321321321313213213213", hex.EncodeToString(targetKvbs))
	privKey := new(SM2PrivateKey)
	_, err := privKey.Bytes()
	assert.NotNil(t, err)
	testBytes := make([]byte, 33)
	assert.Equal(t, privKey.FromBytes(testBytes, 0).Error(), "key length is empty or too long")
	assert.Equal(t, privKey.FromBytes(testBytes[:0], 0).Error(), "key length is empty or too long")
	_, err = privKey.Bytes()
	assert.NotNil(t, err)
}
func TestSM2PublicKey_PublicKey(t *testing.T) {
	key, err := GenerateSM2Key()
	assert.Nil(t, err)
	keyBytes, err := key.Bytes()
	assert.Nil(t, err)
	sk := new(SM2PrivateKey)
	assert.Equal(t, sk.K, zeroKey)
	assert.Equal(t, sk.PublicKey.X, zeroKey)
	assert.Equal(t, sk.PublicKey.Y, zeroKey)
	assert.Nil(t, sk.FromBytes(keyBytes, 0))
	pk := sk.Public()
	assert.NotEqual(t, pk.(*SM2PublicKey).X, zeroKey)
	assert.NotEqual(t, pk.(*SM2PublicKey).Y, zeroKey)
	b := sm2.Sm2().IsOnCurve(new(big.Int).SetBytes(sk.PublicKey.X[:]), new(big.Int).SetBytes(sk.PublicKey.Y[:]))
	assert.True(t, b)
}
func TestSignAndVerify(t *testing.T) {
	for i := 0; i < 0xffff; i++ {
		priv, err := GenerateSM2Key()
		assert.Nil(t, err)
		pub := priv.PublicKey
		h := HashBeforeSM2(&pub, []byte(msg))
		s, err := priv.Sign(nil, h, rand.Reader)
		assert.Nil(t, err)
		b, err := pub.Verify(nil, s, h)
		assert.True(t, b)
		assert.Nil(t, err)
	}
}

func TestPrivateKeyBytesAndFromBytes(t *testing.T) {
	for i := 0; i < 99; i++ {
		priv, err := GenerateSM2Key()
		assert.Nil(t, err)
		bs, err := priv.Bytes()
		assert.Nil(t, err)

		newPriv := new(SM2PrivateKey)
		assert.Nil(t, newPriv.FromBytes(bs, 0))

		assert.Equal(t, priv.K, newPriv.K)
	}
}

func TestPublicKeyBytesAndFromBytes(t *testing.T) {
	for i := 0; i < 990; i++ {
		priv, err := GenerateSM2Key()
		assert.Nil(t, err)
		pub := priv.PublicKey
		bs, err := pub.Bytes()
		assert.Nil(t, err)

		newPub := new(SM2PublicKey)
		assert.Nil(t, newPub.FromBytes(bs, 0))

		assert.Equal(t, newPub.X, pub.X)
		assert.Equal(t, newPub.Y, pub.Y)
	}
}

func TestSM2SignAndVerify(t *testing.T) {
	priv, err := GenerateSM2Key()
	assert.Nil(t, err)
	pub := priv.PublicKey
	h := HashBeforeSM2(&pub, []byte(msg))
	sm2 := NewSM2()
	privb, err := priv.Bytes()

	assert.Nil(t, err)
	s, err := sm2.Sign(privb, h, rand.Reader)
	assert.Nil(t, err)

	pubb, err := pub.Bytes()
	assert.Nil(t, err)
	b, err := sm2.Verify(pubb, s, h)
	assert.True(t, b)
	assert.Nil(t, err)
}

func TestGetPublicKey(t *testing.T) {
	priv, err := GenerateSM2Key()
	assert.Nil(t, err)
	bs, err := priv.Bytes()
	assert.Nil(t, err)

	newPriv := new(SM2PrivateKey)
	assert.Nil(t, newPriv.FromBytes(bs, 0))

	privateKey := newPriv.CalculatePublicKey()
	pubKey := priv.PublicKey
	newPubKey := privateKey.PublicKey
	bytes, err := pubKey.Bytes()
	assert.Nil(t, err)
	newBytes, err := newPubKey.Bytes()
	assert.Nil(t, err)
	assert.Equal(t, bytes, newBytes)

	privateKey = newPriv.SetPublicKey(&newPubKey)
	newPubKey = privateKey.PublicKey
	newBytes, err = newPubKey.Bytes()
	assert.Nil(t, err)
	assert.Equal(t, bytes, newBytes)

	assert.Equal(t, priv.K, newPriv.K)
}

func BenchmarkSign(b *testing.B) {
	msg := make([]byte, 961)
	_, _ = rand.Read(msg)
	priv, err := GenerateSM2Key()
	assert.Nil(b, err)
	pub := priv.PublicKey
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StartTimer()
		h1 := HashBeforeSM2(&pub, msg)
		s, err := priv.Sign(nil, h1, rand.Reader)
		b.StopTimer()
		assert.Nil(b, err)
		h2 := HashBeforeSM2(&pub, msg)
		bb, err := pub.Verify(nil, s, h2)
		assert.True(b, bb)
		assert.Nil(b, err)
	}
} //BenchmarkSign-4   	    2512	    490509 ns/op

func BenchmarkVerify(b *testing.B) {
	msg := make([]byte, 961)
	_, _ = rand.Read(msg)
	priv, err := GenerateSM2Key()
	assert.Nil(b, err)
	pub := priv.PublicKey
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h1 := HashBeforeSM2(&pub, msg)
		s, err := priv.Sign(nil, h1, rand.Reader)
		assert.Nil(b, err)
		b.StartTimer()
		h2 := HashBeforeSM2(&pub, msg)
		bb, err := pub.Verify(nil, s, h2)
		b.StopTimer()
		assert.True(b, bb)
		assert.Nil(b, err)
	}
} //BenchmarkVerify-4   	    2965	    392947 ns/op

func BenchmarkGenerateSM2KeyForDH(b *testing.B) {
	privateA, _ := GenerateSM2Key()
	privateB, _ := GenerateSM2Key()
	priv1, _ := GenerateSM2Key()
	randA := priv1.K

	priv2, _ := GenerateSM2Key()
	randBG := priv2.Public().(*SM2PublicKey)

	publicA := privateA.Public().(*SM2PublicKey)
	publicB := privateB.Public().(*SM2PublicKey)
	idA := intToBytes(1)
	idB := intToBytes(2)
	dA := new(big.Int).SetBytes(privateA.K[:])
	pAX := new(big.Int).SetBytes(publicA.X[:])
	pAY := new(big.Int).SetBytes(publicA.Y[:])
	pBX := new(big.Int).SetBytes(publicB.X[:])
	pBY := new(big.Int).SetBytes(publicB.Y[:])
	for i := 0; i < b.N; i++ {
		b.StartTimer()
		xA, yA, zA, err := GenerateSM2KeyForDH(idA, idB, randA[:], dA, pAX, pAY, pBX, pBY, randBG, true)
		b.StopTimer()
		assert.NotNil(b, xA)
		assert.NotNil(b, yA)
		assert.NotNil(b, zA)
		assert.Nil(b, err)

	}

}

func TestSignCase(t *testing.T) {
	type args struct {
		dgst   string
		reader string
		sk     string
	}
	tests := []struct {
		name    string
		args    args
		sig     string
		pk      string
		rs      string
		wantErr bool
	}{
		{"sm2sig1",
			args{"2D346578282A787D7B697A6427224A5B302923614C44527778224545576F2439",
				"79473D5D4A465A6876532D5422715D5156666B6744563D337732745C5D355A61",
				"62765C596F685E4929705F385946635D430048773D56412675265C436B5C7157"},
			"",
			"35CFDF8F83ADD9646664EF65EDB0FD033EB9F589F32E494EE4E16067F7057B9049" +
				"10498DDCDC93AF41481A73D6961ED76ECC66E871E8314692F8AECCC14B900D",
			"b73c0dd347f7dc6e802c347e32751d71dda3168f92d9d72fae8b6a3f82bd54ddda" +
				"7e47ea4fe807db013bd6af1f984a9d107fbc9f8c50194a47765013f9e12edf",
			false},
		{"sm2sig2",
			args{"5C3472494232447454504A5E40713478304746696334793229424A5B59762670",
				"5766235E616733484751305D7B4A6F27466A743754524F34717646466C534967",
				"534C5D395047337D55356468392D393D2B41445479264B235A48686540662B67"},
			"",
			"17734F64A01A78B8A7076AE67A46E45574B13E35A29C17E5DEC5B8A6878F45485EC5" +
				"391051F45DE119393B833621901196DE8F923A2D6B8E90E4FF0B3308EC42",
			"b9b4bcf7d908293682ac076884b356c2b56cf638d3b51008b2b31cb5eb3333d02ab2ea" +
				"1ecbf60b64b6660f119eb2bb89f6905fe3d44db1f5cc89771d6a7ad0f3",
			false},
		{"sm2sig3",
			args{"276B465368324869744B4E28735A5077694B24243274213928526756614E525D",
				"72440058504D63236E6558454332774B454C61432378545132485D306A7D6454",
				"5036386262545E234B334B6A526C6D686A4E50514E5F336566255D66523D5C53"},
			"",
			"68A8BCB82807BB209C7EE765E7CF6A317DAFE3E1CE4FF92168B5893F59F995535A1465" +
				"5D0804FB28C2620B2812BAB2686E9E829EC132ACC26F60712F84A0757A",
			"22d0b8e57626582a249c133ee7c6b3601ab7f02655112430ebc452502c29e31abac1c0b9" +
				"87c3396d8ee56974543c334dc36add34857b11f8cd5691615d5dc378",
			false},
		{"sm2sig4",
			args{"7433236A554F585F2B36215E2736505E48552B686E74506B5E44506A665D5275",
				"27426D4C772D6C4E6F4625317076212332262D517B55237330594F5B42285F27",
				"6976743D7B314F626D267A74575F497B4C45622231304628536F473476327A58"},
			"",
			"7829B492CCBDCD5ED7B22DA4588E7FC751F30952456DBDC036FC8295DF16FAD08122EE" +
				"AE45AA98F7905085810B1775E4E94F3D856FB3DFC37D1AAE1EE33DACE7",
			"71708ce6481bf1d8e23928c5250b07d883d9f014fc2a0672734b720414502942b685c45ffe5573e49ee5fc3babe8824ac05dcde094986eef800120bcf23ade31",
			false},
		{"sm2sig5",
			args{"45623472254B64526132664C6B752973795055563863744A5236504C405C795D",
				"56436148706532335D4F6231684C4A48782648544E6B2731363225437D662666",
				"325A343D6C65396A27573436296E22717D542D267021575C4D4A4A2D502A566D"},
			"",
			"6F3BD77DB315B8ACBF0D1920F562678B3076D77948C7DA0FE6DAFC2FFFC4B75621F1E" +
				"1DE4E0E64B8DE3C3FE48E60EFDE1613E13BAD60B9B46D3F016A2C4F9946",
			"1e5281459fb80c059c708894328b224b4132560d4f90d01f06b59eb59409f01a9523315" +
				"acfc6a3d3041d5454e08df615481a5caabdd4697d9d10c23417de8974",
			false},
		{"sm2sigGMT1", args{"F0B43E94BA45ACCAACE692ED534382EB17E6AB5A19CE7B31F4486FDFC0D28640", "59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC21", "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8"}, "", "09F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13", "F5A03B0648D2C4630EEAC513E1BB81A15944DA3827D5B74143AC7EACEEE720B3B1B6AA29DF212FD8763182BC0D421CA1BB9038FD1F7F42D4840B69C485BBC1AA", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dgst, _ := hex.DecodeString(tt.args.dgst)
			reader, _ := hex.DecodeString(tt.args.reader)
			sk, _ := hex.DecodeString(tt.args.sk)
			got, _, err := sm2.Sign(dgst, bytes.NewReader(reader), sk)
			if (err != nil) != tt.wantErr {
				t.Errorf("Sign_64bit() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			pk := new(SM2PrivateKey)
			assert.Nil(t, pk.FromBytes(sk, 0))
			assert.NotNil(t, pk, "can not get sk for bytes")
			pk.CalculatePublicKey()
			pkBytes, err := pk.PublicKey.Bytes()
			assert.Nil(t, err)
			//compare pk with tt.pk
			if strings.ToLower(tt.pk) != hex.EncodeToString(pkBytes[1:]) {
				t.Errorf("public key not equal, got =%s, want=%s\n", hex.EncodeToString(pkBytes[1:]), strings.ToLower(tt.pk))
			}
			ok, err := sm2.VerifySignature(got, dgst, pk.PublicKey.X[:], pk.PublicKey.Y[:])
			if !ok || err != nil {
				t.Errorf("signatrue verify faild")
				return
			}

			r, s := sm2.Unmarshal(got)
			r = append(r, s...)
			if strings.ToLower(tt.rs) != hex.EncodeToString(r) {
				t.Errorf("signature invalid, got = %s, want=%s\n", hex.EncodeToString(r), strings.ToLower(tt.rs))
			}
			fmt.Println("(r, s) :", hex.EncodeToString(r))
		})
	}
}

func TestVerify(t *testing.T) {
	type args struct {
		dgst string
		sig  string
		pk   string
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{"sm2verify1",
			args{"59223D3524574F296B26345A6535695E4978366C6269746576385D4728346E41",
				"74F92A342C70C983818C5B92A4096B4EB0F945F0B92AA079C62378C03A6709532B45C56618" +
					"059BF84EDE8D1A3FE067D5DBE7BD3F9ECED17FDCECBF2DAF961204",
				"8E2C3E1163F3C547D09211ABBDE8C15EF0F5C7497470DA006C5D7AAB81846C5B80BBDCB2FB9EC" +
					"44CEB060B71E731191F4CB5A1ACBA5828989A3A9CDE49B6F610"},
			true, false},
		{"sm2verify2",
			args{"387D32416C656A664F4733713457377558755121217D784C566E303D34787B57",
				"6F8A8C4D9E3EF79E3396BF3A40A14D4D82168AF35BB56753A4966BB5A46BB58281DB119CF8CC859" +
					"94808A3346E94C94DCB3DB5FC37B4B7C778974B49356B4880",
				"6421D2DB8D84137AED9BAF300981D7905CA209955C3F5A8FEDDA3F26C6BD32F300F9774C57B2100" +
					"55335783DF3381DDE758C8005F9FEBF5422B602885047C2CB"},
			false, true},
		{"sm2verify3",
			args{"4D407B44453736464E772570377D6629536A5E6329666D6865283527584B5D53",
				"572D12A8CA571DE6B77C0B97137F9AC7EE9149F7E39E38B8C14B30E8B84B05D7641CC08262F95037" +
					"0092F57C190687226626050F868594265DF997A338932AA0",
				"CF8F93D389731C39AB1E5709C8AAA441EB3AD3960E27A4A644A35B7EC6BCC2E602EAE3A1593" +
					"DB87813CBA7D01B0C8D7E71AFCE44D1452D9421C412B084656CDF"},
			true, false},
		{"sm2verify4",
			args{"4E6C3835536352255723287A51235B7A6D71724A4A46714C746E29345347246E",
				"689F0115B988BA31D05B15E8BEC296F57387126626CCCA930511C28894BE723488DE275E64F0DB" +
					"745325FF9AE60576D60B03D3170C3A4F29F24F2EB2FC6DE382",
				"F114E61D2B261330B7D6D3C521DA8EEB33F3B6DCF1D00362EE75B37BDBA7FDFB9180D8A98FAA1" +
					"C9FBEDCC07D27C26616759D81DA9DCC0AC1F344B9534D730E0B"},
			false, true},
		{"sm2verify5",
			args{"786122396E5C49244F456F255B2B237674714D66303933696C7D425B625C4F4B",
				"D83AB25C80B3EF3EB5320F1931131538C671677E4A2D7C1BCCFD24887EAD89EC806CD2D6B56F9F" +
					"BBF8360F9C3B0631AA06CBB71CD9B5AA81FF19B517C8EB5123",
				"491C55C55435D226294DBBF8D97738125D3503D9AFDF3F8D865AB0939D4751D0E7AC89522811BCA" +
					"B8F3DA24930FE7B485EB20CCFEAF9886392987098FABC0095"},
			true, false},
		{"sm2verifyGMT1",
			args{"F0B43E94BA45ACCAACE692ED534382EB17E6AB5A19CE7B31F4486FDFC0D28640",
				"F5A03B0648D2C4630EEAC513E1BB81A15944DA3827D5B74143AC7EACEEE720B3B1B6AA29DF212FD8763182BC0" +
					"D421CA1BB9038FD1F7F42D4840B69C485BBC1AA",
				"09F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020CCEA490CE26775A52DC6EA718C" +
					"C1AA600AED05FBF35E084A6632F6072DA9AD13"},
			true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkBytes := make([]byte, 1, 65)
			pkBytes[0] = 0x04
			pk2, _ := hex.DecodeString(tt.args.pk)
			pkBytes = append(pkBytes, pk2...)
			pk := new(SM2PublicKey)
			assert.Nil(t, pk.FromBytes(pkBytes, 0))
			if pk == nil {
				t.Errorf("can not get publick from %s\n", tt.args.pk)
				return
			}
			dgst, _ := hex.DecodeString(tt.args.dgst)
			sigBytes, _ := hex.DecodeString(tt.args.sig)
			sig := sm2.MarshalSig(sigBytes[:32], sigBytes[32:])
			got, err := sm2.VerifySignature(sig, dgst, pk.X[:], pk.Y[:])
			if (err != nil) != tt.wantErr {
				t.Errorf("Sign_64bit() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("signatue verify faild, test name: %s\n", tt.name)
			}
			//use elliptic.curve
			curve := elliptic.CurveParams{N: sm2.Sm2().Params().N, P: sm2.Sm2().Params().P, Gx: sm2.Sm2().Params().Gx, Gy: sm2.Sm2().Params().Gy, Name: "sm2", BitSize: 256, B: sm2.Sm2().Params().B}
			sm2pk, _ := hex.DecodeString(tt.args.pk)
			ok := curve.IsOnCurve(new(big.Int).SetBytes(sm2pk[:32]), new(big.Int).SetBytes(sm2pk[32:]))
			if !ok {
				t.Errorf("can not get publick from %s\n", tt.args.pk)
			}
		})
	}
}

func TestBeforeSigCase(t *testing.T) {
	type args struct {
		id  string
		pk  string
		msg string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"sm2hash1",
			args{"5D25345F494A725E5044575473626F6A4F68484E5A005F406D264D3123377A34",
				"A027ED7D13D098483A87DFC05CB2DAD6E64A580AD2D3911966150ADEBBAED4B22B" +
					"DDEAADEC110E95C027F59A383AE28BA7328F6153821D662BDC7CE62C85D6E8",
				"50AEFD378EF46ECF43C5EF9746D93693E214B96BC4A2B1DA1A3FC5DF221E456CBD1DEB3" +
					"35A0D96677E0A45A842FED5E676042B9F5C07AF213DB5A01D4E75F5A6"},
			"abab9fd30f5d18773d4ca868c31d68fcd04e772456bb6b7c317b41cba9c1e716"},
		{"sm2hash2",
			args{"7135422763",
				"370E72845703D4897999CC196EEF64D64E8DDE8E36B5AD6EEA1053898BFB14309" +
					"CFF279023F5B2181F27D5687A1FE0352D4756230E4EAB70719C4ED8E08519D6",
				"578E79D8"},
			"241d259e9b6badc22afb8e0c24e0568cc8f7a270f8fc0ec908450f1f0c497d00"},
		{"sm2hash3",
			args{"73674E7678674E6139452A566E2862444D422D466C6330354B4E68397431395D3AE78F",
				"CB737A3D33AC21AEBE8B6A952B5A82E3AE78F54F26F7567A830BF3CCD8B344408929B" +
					"F3A75E73E2B78B8E5E275F60AEC2C9F252F1DDC40D1780592F31D3EBF91",
				"741A56825730E6D01B2A7DA6591349B8"},
			"cd5c2aac5a2e620a529806369c0da83f3146996c6e3ed9be91a90353fd5bf1f0"},
		{"sm2hash4",
			args{"69477D67765F5D6F2D764F4C3D437523664574536B665F422B252736455F3D41",
				"4050D3C5ADDABCACF0F4B958452C734FF943C60AF22603BA5C727C808FFAD894D140951" +
					"1E732C2D711E8C458C685001A66BF661802B0A257B770822F7A12D08B",
				"30452DA5D7AD83A72F34B76F48271246D5ABFD5F4B277CC44FF7DF32913226A62BD852DF528" +
					"236193E83943EA48B9DDFDB4CD5C359266318A223C497353C"},
			"4c844ac60b58e027f4ad4484e1c2e3aa141b7860f62c7a98deb950788f0364a4"},
		{"sm3hash5",
			args{"452A4C5750442656613549725F573650782A38226926545C7939712327492223",
				"A10FB4DE9947B8E9E4926120E033D9905680E8380C2BE057E495126CE62A834960B9E6C" +
					"4BDFE5A0480834F6977483720C3BD09A240CFFB6C0FC09882412F5FD4",
				"1D8D0238E8C1A0015789B19D09EF5B1AA41E2BAE989F04F95468EF1C2D16EE73D5AF99F484" +
					"75AE5170B617764A010005DA33977C65EF1F9106D6AAFEA4E6BCB9"},
			"8d4c220675f6aa49105a5fbca5290297e8f27df516dfde11addd775278e4a2df"},
		{"sm2hashGMT1", args{"31323334353637383132333435363738", "09F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13", "6D65737361676520646967657374"}, "f0b43e94ba45accaace692ed534382eb17e6ab5a19ce7b31f4486fdfc0d28640"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, _ := hex.DecodeString(tt.args.id)
			a := "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC"
			abytes, _ := hex.DecodeString(a)
			pkBytes, _ := hex.DecodeString(tt.args.pk)
			hash := bytes.Join([][]byte{intToBytes(len(id) * 8)[2:], id, abytes, sm2.Sm2().Params().B.Bytes(), sm2.Sm2().Params().Gx.Bytes(), sm2.Sm2().Params().Gy.Bytes(), pkBytes[:32], pkBytes[32:]}, nil)
			za := sm3.Hash(hash)
			msg, _ := hex.DecodeString(tt.args.msg)
			hash = bytes.Join([][]byte{za, msg}, nil)
			got := sm3.Hash(hash)
			if hex.EncodeToString(got) != strings.ToLower(tt.want) {
				t.Errorf("hash with ID is invalid got = %s, want=%s\n", hex.EncodeToString(got), strings.ToLower(tt.want))
			}
			fmt.Println("hash :", hex.EncodeToString(got))
		})
	}
}

//sm2DH
func TestGenerateSM2KeyForDH1(t *testing.T) {
	type args struct {
		idA        string
		idB        string
		randA      string
		privateKey string
		publicAX   string
		publicAY   string
		publicBX   string
		publicBY   string
		RB         string
		keylen     int
		isinit     bool
	}
	tests := []struct {
		name    string
		args    args
		want    string
		want1   string
		want2   string
		key     string
		wantErr bool
	}{
		{"sm2DHAGMT1",
			args{
				"31323334353637383132333435363738",
				"31323334353637383132333435363738",
				"D4DE15474DB74D06491C440D305E012400990F3E390C7E87153C12DB2EA60BB3",
				"81EB26E941BB5AF16DF116495F90695272AE2CD63D6C4AE1678418BE48230029",
				"160E12897DF4EDB61DD812FEB96748FBD3CCF4FFE26AA6F6DB9540AF49C94232",
				"4A7DAD08BB9A459531694BEB20AA489D6649975E1BFCF8C4741B78B4B223007F",
				"6AE848C57C53C7B1B5FA99EB2286AF078BA64C64591B8B566F7357D576F16DFB",
				"EE489D771621A27B36C5C7992062E9CD09A9264386F3FBEA54DFF69305621C4D",
				"ACC27688A6F7B706098BC91FF3AD1BFF7DC2802CDB14CCCCDB0A90471F9BD7072FEDAC0" +
					"494B2FFC4D6853876C79B8F301C6573AD0AA50F39FC87181E1A1B46FE",
				16,
				true},
			"c558b44bee5301d9f52b44d939bb59584d75b9034dd6a9fc826872109a65739f",
			"3252b35b191d8ae01cd122c025204334c5eacf68a0cb4854c6a7d367ecad4de7",
			"c558b44bee5301d9f52b44d939bb59584d75b9034dd6a9fc826872109a65739f" +
				"3252b35b191d8ae01cd122c025204334c5eacf68a0cb4854c6a7d367ecad4de" +
				"73b85a57179e11e7e513aa622991f2ca74d1807a0bd4d4b38f90987a17ac245b" +
				"179c988d63229d97ef19fe02ca1056e01e6a7411ed24694aa8f834f4a4ab022f7",
			"6C89347354DE2484C60B4AB1FDE4C6E5",
			false},
		{"sm2DH1-A",
			args{"246A4C496D746561467D6E655C6B2A69784279773428572A5E64246D576A6C3D",
				"773478453878676A445A46525C52503D4344634663213D434D5135405F715D47",
				"7A6F2B7D546179636B3938414C715D787D77384D24517258404476234B4E3545",
				"542A625F30577340316A512D63317354786921583821222828766B2673527028",
				"FAB4DDE159CFB379D175D956F0498C4D559FE6028585997CF72AC9190BBE9F84",
				"D8ECADF74AAD56931903A978F4F0CC90DD009C36B614DEF09F89DBFE3829D797",
				"604D4A8ED38C7BE9EE1C322D94B9B14CB2804C6C252A6A6B3E5BC4AC3CCDFE46",
				"4C082E4A2C20ED682816B6CC8A93F2F91E75476C6E6427B50916D49BA37B435C",
				"54FCB6212A88D2DC553EB99004F395DF2A7F18E4A02375D20CE20F4C0B285E7FF24E5" +
					"F6717D58CB5C1A393A532C1921C3AF97AC5E6A480C1A31AA1013C02E5E6",
				16,
				true},
			"2ae388de45c5a345dff250b2cded2d40a61504a56e98a28f2e693ff341ec62ee",
			"416518ae40252d999a0e2529dfd1c0b04f00e797fc12cc2baa4e9328efcdce01",
			"2ae388de45c5a345dff250b2cded2d40a61504a56e98a28f2e693ff341ec62ee416518ae" +
				"40252d999a0e2529dfd1c0b04f00e797fc12cc2baa4e9328efcdce01fb77c8cc0cb327bb" +
				"173e2ef2b25a1b5c9a76cd3c070decdfe08b7071611fe142ffb59fcad0daee477ad6857f" +
				"2ff80290cdbeb826d488a309bf2c355e70b98372",
			"e94749e7a02cc2f25cf4b6d01d50c456",
			false},
		{"sm2DH1-B",
			args{"773478453878676A445A46525C52503D4344634663213D434D5135405F715D47",
				"246A4C496D746561467D6E655C6B2A69784279773428572A5E64246D576A6C3D",
				"2138403879644179455146756D396D445971684A5F297100235669767563556F",
				"462B6D432943314276614323724F2D2732797425754731305C466E4A4D442673",
				"604D4A8ED38C7BE9EE1C322D94B9B14CB2804C6C252A6A6B3E5BC4AC3CCDFE46",
				"4C082E4A2C20ED682816B6CC8A93F2F91E75476C6E6427B50916D49BA37B435C",
				"FAB4DDE159CFB379D175D956F0498C4D559FE6028585997CF72AC9190BBE9F84",
				"D8ECADF74AAD56931903A978F4F0CC90DD009C36B614DEF09F89DBFE3829D797",
				"2771495B51974FC9E95F3036ADE1D453B4FEC9A531E8D1D70D3D2C6B18E62889AEBF3B" +
					"58967C5A55662A785B4C573DF969082E1D1C8A47C28D36DABEC30AD9D9",
				16,
				false},
			"2ae388de45c5a345dff250b2cded2d40a61504a56e98a28f2e693ff341ec62ee",
			"416518ae40252d999a0e2529dfd1c0b04f00e797fc12cc2baa4e9328efcdce01",
			"2ae388de45c5a345dff250b2cded2d40a61504a56e98a28f2e693ff341ec62ee416518a" +
				"e40252d999a0e2529dfd1c0b04f00e797fc12cc2baa4e9328efcdce01fb77c8cc0cb32" +
				"7bb173e2ef2b25a1b5c9a76cd3c070decdfe08b7071611fe142ffb59fcad0daee477ad" +
				"6857f2ff80290cdbeb826d488a309bf2c355e70b98372",
			"e94749e7a02cc2f25cf4b6d01d50c456",
			false},
		{"sm2DH2-A",
			args{"4F7651756352756C65764D794F5D597842344B46594D2A396826564E6B68507B",
				"456D24324C475B69366D7647286C714674294158216D512D5F294A4D4B7B3676",
				"73437531226F5851426B386D6F5F344039004533307A574246627A5F79593553",
				"282B254636375A3340387D5B6D5D696C7752515D7D6A584529445F3D527A6A39",
				"54837732DF5106636666AB0D956E8A4AD40987E42EE03A451D8F9A5B2BD6777E",
				"01B92BE10334B22897A6733971F8BD141411A5F4610B3A7005DF000450943FB3",
				"4C68C24C9EBEABA1AC5133E62611425BEE1583479998C7B3158CA9D31BCFA714",
				"43D4AC04E195E3B877C017016BA82FCDD78FBC8A2F52EC736811318C890E82FE",
				"8573FF143CF27F7D60016DD9C934521806D011941887F663E0CC6379671B1E8FD9513F08" +
					"9B32AEF98EB177AB318A9C1567AB7764E1EB4AAC4D262E9F105C1ABA",
				32,
				true},
			"b3fbad13d1994db99d2666094d08b7d508bb2fa23fa122f4ea2d43bcab348760",
			"066dec3ec650e54c7585966888fd080f940bf1a845e25299428ae43b8c4aa6ea",
			"b3fbad13d1994db99d2666094d08b7d508bb2fa23fa122f4ea2d43bcab348760066dec3ec650e" +
				"54c7585966888fd080f940bf1a845e25299428ae43b8c4aa6ea35a470c5eb515f416c5dcef3d72fe" +
				"2d0f521e75d481f59f095c3c52741d2f5819960e0f1de83fb09d6e7eb440e0ea8cb572512900bb9eb91d6855c62ffeb8a8b",
			"57cb22fa04fea002db3526ab5b09f0478729646e71dee4a51e38576dba48d696", false},
		{"sm2DH2-B",
			args{"456D24324C475B69366D7647286C714674294158216D512D5F294A4D4B7B3676",
				"4F7651756352756C65764D794F5D597842344B46594D2A396826564E6B68507B",
				"386C27424239247157385D377228494C457434665A7B7743524E547170444723",
				"68554640237476564545405C5976287B764171796D3835625D65774F6D4B3D54",
				"4C68C24C9EBEABA1AC5133E62611425BEE1583479998C7B3158CA9D31BCFA714",
				"43D4AC04E195E3B877C017016BA82FCDD78FBC8A2F52EC736811318C890E82FE",
				"54837732DF5106636666AB0D956E8A4AD40987E42EE03A451D8F9A5B2BD6777E",
				"01B92BE10334B22897A6733971F8BD141411A5F4610B3A7005DF000450943FB3",
				"A638D574F0020031211427D6AE04E84C5FBF399056F14B3CBFC3D12CB79EC1CE896AB" +
					"FD8B1EE117149B6C96A7A454788858D470861461B812AB67688DFB4F17F",
				32,
				false},
			"b3fbad13d1994db99d2666094d08b7d508bb2fa23fa122f4ea2d43bcab348760",
			"066dec3ec650e54c7585966888fd080f940bf1a845e25299428ae43b8c4aa6ea",
			"b3fbad13d1994db99d2666094d08b7d508bb2fa23fa122f4ea2d43bcab348760066dec3ec" +
				"650e54c7585966888fd080f940bf1a845e25299428ae43b8c4aa6ea35a470c5eb515f416c5dcef3d72" +
				"fe2d0f521e75d481f59f095c3c52741d2f5819960e0f1de83fb09d6e7eb440e0ea8cb572512900bb9eb91d6855c62ffeb8a8b",
			"57cb22fa04fea002db3526ab5b09f0478729646e71dee4a51e38576dba48d696",
			false},
		{"sm2DH3-A",
			args{"78432B352631485A2B5E7062",
				"40513958347D2925302A684971",
				"6A576B554C382B69236649525E344643745C24393548322A5E637228452D2B55",
				"412766756A4F265A4C212A217855536E4772575477336C26496C6E25544C6B2A",
				"70407275882EBA774546669B875D9C564C0BB22C5668AC70483117F226C3BB3E",
				"ECAC827122BFD730660FF15905132ACCF769FD46D7EC21AA6E639EACCE5B767D",
				"18C7C946E425321A5C417F36D681B6D5E1AC7359B39F4318BD5DD5BC9A1C9453",
				"C8CB1D04B1B8F91AC990E73F9B58904D086006ED09B9FDC575576879891E641F",
				"F319713C74914ED73FAE735CF64226BE3C42FA67DEB06788CB4457F19654014AF08C66D78BC" +
					"9AB541675BD7FEE2F0243923872B6736C403752EB38EFA5231DA6",
				32,
				true},
			"5684ddaaf581183efcaf5dbab9c2f0fb5da87a35f491a726c4ad0aa747d62d3e",
			"ec0e968c0a2e0c77f890426ce8b849ba1d7d9ee774f8453d22859c411950ce00",
			"5684ddaaf581183efcaf5dbab9c2f0fb5da87a35f491a726c4ad0aa747d62d3eec0e968c0a2e0c77f" +
				"890426ce8b849ba1d7d9ee774f8453d22859c411950ce00ae9340173f5e6f2a3cc158f96833cc901b" +
				"14cd07ca6ddad345b6f83feb9dbcffba0f6c3502655966459cfe29600173bd1c2bc8ad5dfa9a701c60cb7fd501fce6",
			"c2c20b2a9af5f6b09dde05c132dda3197416f2da5544b2264975b480a3e8ea6a",
			false},
		{"sm2DH3-B",
			args{"40513958347D2925302A684971",
				"78432B352631485A2B5E7062",
				"215B5633495E726979266550704E532B645D7A4C5958223734754F2D5F2B6E49",
				"485F4D26004F29643858592B393528217B454A2D517453686A655B2A694D494F",
				"18C7C946E425321A5C417F36D681B6D5E1AC7359B39F4318BD5DD5BC9A1C9453",
				"C8CB1D04B1B8F91AC990E73F9B58904D086006ED09B9FDC575576879891E641F",
				"70407275882EBA774546669B875D9C564C0BB22C5668AC70483117F226C3BB3E",
				"ECAC827122BFD730660FF15905132ACCF769FD46D7EC21AA6E639EACCE5B767D",
				"1F75572B8911BAD63B6070BD9A3FA8A3354138B62D8756908BA679578C47215186A03242D7A32539A" +
					"294A299B68660973FC9479F6EF17130A5BC86155519D0F3",
				32,
				false},
			"5684ddaaf581183efcaf5dbab9c2f0fb5da87a35f491a726c4ad0aa747d62d3e",
			"ec0e968c0a2e0c77f890426ce8b849ba1d7d9ee774f8453d22859c411950ce00",
			"5684ddaaf581183efcaf5dbab9c2f0fb5da87a35f491a726c4ad0aa747d62d3eec0e968c0a2e0c77f8904" +
				"26ce8b849ba1d7d9ee774f8453d22859c411950ce00ae9340173f5e6f2a3cc158f96833cc901b14cd07ca6" +
				"ddad345b6f83feb9dbcffba0f6c3502655966459cfe29600173bd1c2bc8ad5dfa9a701c60cb7fd501fce6",
			"c2c20b2a9af5f6b09dde05c132dda3197416f2da5544b2264975b480a3e8ea6a",
			false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idA, _ := hex.DecodeString(tt.args.idA)
			idB, _ := hex.DecodeString(tt.args.idB)
			randA, _ := hex.DecodeString(tt.args.randA)
			privateKeyBytes, _ := hex.DecodeString(tt.args.privateKey)
			publicAX, _ := hex.DecodeString(tt.args.publicAX)
			publicAY, _ := hex.DecodeString(tt.args.publicAY)
			publicBX, _ := hex.DecodeString(tt.args.publicBX)
			publicBY, _ := hex.DecodeString(tt.args.publicBY)
			randBGBytes, _ := hex.DecodeString(tt.args.RB)
			randBGBytes = bytes.Join([][]byte{{0x04}, randBGBytes}, nil)
			RB := new(SM2PublicKey)
			assert.Nil(t, RB.FromBytes(randBGBytes, 0))
			got, got1, got2, err := GenerateSM2KeyForDH(idA, idB, randA, new(big.Int).SetBytes(privateKeyBytes), new(big.Int).SetBytes(publicAX), new(big.Int).SetBytes(publicAY), new(big.Int).SetBytes(publicBX), new(big.Int).SetBytes(publicBY), RB, tt.args.isinit)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateSM2KeyForDH() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if hex.EncodeToString(got.Bytes()) != tt.want {
				t.Errorf("GenerateSM2KeyForDH() got=%v, want=%v", hex.EncodeToString(got.Bytes()), tt.want)
			}
			if hex.EncodeToString(got1.Bytes()) != tt.want1 {
				t.Errorf("GenerateSM2KeyForDH() got1 = %v, want %v", hex.EncodeToString(got1.Bytes()), tt.want1)
			}
			if hex.EncodeToString(got2) != tt.want2 {
				t.Errorf("GenerateSM2KeyForDH() got2 = %v, want %v", hex.EncodeToString(got2), tt.want2)
			}
			key := sm2DHKdf(got2, tt.args.keylen)
			if hex.EncodeToString(key) != strings.ToLower(tt.key) {
				t.Errorf("con not get corret key from kdf, got=%s, want=%s\n", hex.EncodeToString(key), strings.ToLower(tt.key))
			}
			fmt.Println("key is", hex.EncodeToString(key))
		})
	}
}

func TestName(t *testing.T) {
	Byte2Uint32 := func(s []byte) []uint32 {
		Ruint := make([]uint32, 8)
		for i := 0; i < 8; i++ {
			Ruint[7-i] = binary.BigEndian.Uint32(s[i*4 : (i+1)*4])
		}
		return Ruint
	}
	dgstBytes, _ := hex.DecodeString("59223D3524574F296B26345A6535695E4978366C6269746576385D4728346E41")
	sigBytes, _ := hex.DecodeString("74F92A342C70C983818C5B92A4096B4EB0F945F0B92AA079C62378C03A6709532B45C56618059BF84EDE8D1A3FE067D5DBE7BD3F9ECED17FDCECBF2DAF961204")
	pkBytes, _ := hex.DecodeString("8E2C3E1163F3C547D09211ABBDE8C15EF0F5C7497470DA006C5D7AAB81846C5B80BBDCB2FB9EC44CEB060B71E731191F4CB5A1ACBA5828989A3A9CDE49B6F610")
	dgst := Byte2Uint32(dgstBytes)
	sigR := Byte2Uint32(sigBytes[:32])
	sigS := Byte2Uint32(sigBytes[32:])
	pkX := Byte2Uint32(pkBytes[:32])

	var in []uint32
	in = append(in, sigS...)
	in = append(in, sigR...)
	in = append(in, pkX...)
	in = append(in, dgst...)

	for i := range in {
		fmt.Printf("0x%d,", in[i])
	}
	fmt.Println(len(in))
}

func printBytes(in []byte) {
	ret := "[]byte{"
	for _, v := range in {
		ret += fmt.Sprintf("0x%02x, ", v)
	}
	ret += "}"
	fmt.Println(ret)
}

func TestGetSM3IDHasher(t *testing.T) {
	var rander32 = bytes.NewBuffer(bytes.Repeat([]byte("1"), 128))
	k, _ := GenerateSM2Key()
	priv, _ := k.Bytes()
	pub, _ := k.PublicKey.Bytes()
	printBytes(priv)
	printBytes(pub)
	s, err := k.Sign(nil, []byte("flato"), rander32)
	assert.Nil(t, err)
	printBytes(s)
}
