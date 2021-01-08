package sm2

import (
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func TestSm2Curve_Params(t *testing.T) {
	para := Sm2().Params()
	assert.NotNil(t, para)
	target, _ := new(big.Int).SetString("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16)
	assert.True(t, target.Cmp(para.B) == 0)
}

func TestSm2Curve_Add(t *testing.T) {
	para := Sm2().Params()
	e := Sm2()
	a, b := e.ScalarBaseMult(big.NewInt(3).Bytes())
	c, d := e.Double(para.Gx, para.Gy)
	c, d = e.Add(c, d, para.Gx, para.Gy)
	assert.True(t, a.Cmp(c) == 0)
	assert.True(t, b.Cmp(d) == 0)
}

func TestSm2Curve_IsOnCurve(t *testing.T) {
	e := Sm2()
	a, b := e.ScalarBaseMult(big.NewInt(5201314).Bytes())
	assert.True(t, e.IsOnCurve(a, b))
}

func TestSm2Curve_ScalarMult(t *testing.T) {
	e := Sm2()
	para := e.Params()
	a, b := e.ScalarBaseMult(big.NewInt(5201314).Bytes())
	c, d := e.ScalarMult(para.Gx, para.Gy, big.NewInt(5201314).Bytes())
	assert.True(t, e.IsOnCurve(a, b))
	assert.Equal(t, a.Text(16), c.Text(16))
	assert.Equal(t, b.Text(16), d.Text(16))
}

//func TestPrecomputed(t *testing.T){
//	t.Skip()
//	precomputedOnce.Do(InitTable)
//	for i := 0; i< 43; i++{
//		for j := 0; j< 32; j++{
//			pointx , pointy := new(sm2FieldElement), new(sm2FieldElement)
//			copy(pointx[:],sm2Precomputed[i][j*18:j*18 + 9])
//			copy(pointy[:],sm2Precomputed[i][j*18+9: j*18 + 18])
//			bigX :=sm2ToBig(pointx)
//			bigY := sm2ToBig(pointy)
//			fmt.Println(bigX.Text(16))
//			fmt.Println(bigY.Text(16))
//		}
//	}
//}
