package sm3_test

import (
	"crypto/rand"
	"encoding/hex"
	"github.com/meshplus/crypto-gm/internal/sm3"
	"github.com/stretchr/testify/assert"
	"hash"
	"testing"
)

//BenchmarkSm3-4   	  157723	      6730 ns/op	    1176 B/op	       6 allocs/op
//BenchmarkSm3-4   	  200000	      6465 ns/op	     160 B/op	       2 allocs/op
func BenchmarkSm3(t *testing.B) {
	msg := make([]byte, 1024)
	_, _ = rand.Read(msg)
	t.ReportAllocs()
	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		sm3.Hash(msg)
	}
}

func TestSignHashSM3(t *testing.T) {
	X, _ := hex.DecodeString("86d3205ed0c3db8ef35a74b6bf924cbef75988e835f65f422884e3b1c8cdbde1")
	Y, _ := hex.DecodeString("ea7eee5e7ff177622c3081aea9375d3cfec41867298261aae8f8e1434c9e81f0")
	msg := []byte("1234567812345678123456781234567812345678123456789")
	hash := "3e4fc55b2a857eff8fddd01bb98cec95443780585dda78aa005b38df1e090ec6"
	h1 := sm3.SignHashSM3(X, Y, msg)
	assert.Equal(t, hex.EncodeToString(h1), hash)
}

func TestSM3_Sum(t *testing.T) {
	//结论，sum的返回值总是对的(append后的结果)，如果传入参数则参数的cap-len一定大于32就能提高性能
	//如果传入参cap-len不够32，那么因为append的"要么成功要么不动"则不会影响入参的值
	type args struct {
		len int
		cap int
	}
	tests := []struct {
		name string
		args args
		res  string
		hash string
	}{
		{"sumWithCap32", args{0, 32}, "c72f9d4a17ca8d01b082063856d1d376314013e00ec5215e103a7421f2290cd2", "c72f9d4a17ca8d01b082063856d1d376314013e00ec5215e103a7421f2290cd2"},
		{"sumWithCap64", args{32, 64}, "0000000000000000000000000000000000000000000000000000000000000000c72f9d4a17ca8d01b082063856d1d376314013e00ec5215e103a7421f2290cd2", "0000000000000000000000000000000000000000000000000000000000000000c72f9d4a17ca8d01b082063856d1d376314013e00ec5215e103a7421f2290cd2"},
		{"sumWithCap15", args{0, 15}, "000000000000000000000000000000", "c72f9d4a17ca8d01b082063856d1d376314013e00ec5215e103a7421f2290cd2"},
	}
	msg := []byte("b613b75576e2b59ef88d76bce6ccb5cbde2c53e39c90d5edcd1e3a3be33b212daa211072748715b066ddc8492113ba594ca94b47652a1b6daebd4e4a2c4e2b89b4465cdef2c39b12b86e36a5e6ff5d699807213cc54488c2a84d22d3a43b3a09fe146e48f71555e04c945551b64027092a726af125686e99c74e8a3bd57860d45000351cf08010889e47b1084bc68f1787dabdca6d4d2b39e979ad1c281c2383842722b318c26ba900881c2cbbeaa54a7a3a8f8e86a8bb16e94b40043d9076b4dae1ddccab6271a6673605f4b1b770342295f276f493d71c00abc6c2494aeb7ee2e1ca10d2774ec4705355041ca6864c2f93922bbe612b1ed479b9cdda825cfa2ea4b4cff3513150dccdca5a23b10d16d7ea730ff405cbaa2d2ee04854b114eb281d8821ca70331ea94b4e3e8144c65e0f7a9933745258e9aea716a88aa59ed4982718b00696e92839a481313bbc49594b1c7a66ae5c315cf484617885f5750d10f261c9bde69628e9b5a97f3529f23e7d0ba62c0e3e9a793c27b0ab05543954f4399a0a1cbe8143022fefc124ef6a0e50514e53a75fb2a79af7504dbde31a2526175386f679097618eaab86934fa00d58f8a9eedaf95c01fafbe4f4d416d1a2440c21cb6a30a8b958994a8bb988d657e2315c6c9608d81b6bf34835749989947107b14b6a23956cbbe1143aab3ee4da43bca139c5bb618d8650c5557e34467fb8ea5aec2ebd8b09391c0aa2e3a520b918c80c11b4d3b1f118f88eaa8a592bbdd378044322b5fef72c27172912c621d933a7ca2b5ba0ad4db40ec8e0dc8b8f56be180937f21be1ce5bd066d5db25ec4d477e6d0382a6e744824f6943b0a4db9c4928408fcd14fc2bde1d2e7f02fbe9f99ee0f68f538b42a9ac18d6363cad271ed65046289b579f465fbc324f44edc32ffe77098743ebc6929ed6b6e2b148ba9e4a3c555feba2a2b88e242c71d44a8a00001029c6dadd7c2c01927525da87087ad6790b381a5030135887cc9888ec697296839c9c38021850c47ec539cd03a98879bfe2c8da9e37618c5e81cc6b79b306ca396a182180b52ed36768cfbe5be943ad7c530fd5c407bf8163378cd235818fa671290cd21b51cc260d5aad37489643985f3cbfc9e7ab2ec31e0e3dfbed9ef67c57fe9af40711c017f8e047d67712a22b6a3ab0876977a74ebf14033d36a3393bc29f817722ed20d7ddedc3e97110691d9ac8fd30f7bb58e7736d5393c3686c0e2c5273b17e6997a5343e2ee0434a015d4e4a002a37905d509187a3998331a736f250476fb553bbc3c9ba43304dfd4e1eaa50f8078f55b8d42ad8689fd79dabf70f5e838925c71d0411f45185a39de1f3c3662aae00f65ae4b2cdebf57349e78429b6513dc0219c8e5710755c8a825693c08aa5b23352b09980a8252e1de4fb4a71014dce72fd5337c5eb9653ffc8ed")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hw := sm3.New()
			_, _ = hw.Write(msg)
			res := make([]byte, tt.args.cap)
			got := hw.Sum(res[:tt.args.len])
			if hex.EncodeToString(got) != tt.hash {
				t.Errorf("hash value incorret want = %s, got =%s", tt.hash, hex.EncodeToString(got))
			}
			if hex.EncodeToString(res) != tt.res {
				t.Errorf("hash did not append to res, want = %s, res = %s", tt.res, hex.EncodeToString(res))
			}
		})
	}
}

func TestWriteMultiTimes(t *testing.T) {
	h, _ := hex.DecodeString("01020304050607080900010203040506070809000102030405060708090001020304050607080900010203040506070809")

	hr := &sm3.SM3{}
	hr.Reset()
	hexTo(h, hr)
	hexTo(h, hr)
	ret := make([]byte, 0, 32)
	ret = hr.Sum(ret)

	hr = &sm3.SM3{}
	hr.Reset()
	w1, _ := hex.DecodeString("30313032303330343035303630373038303930303031303230333034303530363037303830393030303130323033303430353036303730383039303030313032")
	w2, _ := hex.DecodeString("30333034303530363037303830393030303130323033303430353036303730383039")
	_, _ = hr.Write(w1)
	_, _ = hr.Write(w2)
	_, _ = hr.Write(w1)
	_, _ = hr.Write(w2)

	ret3 := make([]byte, 0, 32)
	ret3 = hr.Sum(ret3)
	assert.Equal(t, ret, ret3)
}

func hexTo(src []byte, hr hash.Hash) {
	var buf [64]byte
	if len(src) == 0 {
		_, _ = hr.Write([]byte{'0'})
		return
	}
	cycNum := len(src) >> 5
	s := 0
	for i := 0; i < cycNum; i++ {
		hex.Encode(buf[:], src[s:s+32])
		_, _ = hr.Write(buf[:])
		s += 32
	}

	if s == len(src) {
		return
	}

	hex.Encode(buf[:(len(src)-s)*2], src[s:])
	_, _ = hr.Write(buf[:(len(src)-s)*2])
}
