package sm2

import (
	"crypto/rand"
	"encoding/asn1"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

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
		b2 := marshal(r.Bytes(), s.Bytes())
		assert.Equal(t, b1, b2)
		asn1.Unmarshal(b1, &sig)
		x, y := unMarshal(b2)
		assert.Equal(t, sig.R.Bytes(), x)
		assert.Equal(t, sig.S.Bytes(), y)
	}
}
