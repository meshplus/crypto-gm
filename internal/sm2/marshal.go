package sm2

// 0    | 1    | 2    | 3  | 4    | 4+xl  | 5+xl | 6+xl
// 0x30 | xy+4 | 0x02 | xl | ____ | 0x02  | yl   | ____
func marshal(x, y []byte) []byte {
	offset := 0
	for ; x[offset] == byte(0); offset++ {
	}
	x = x[offset:]
	offset = 0
	for ; y[offset] == byte(0); offset++ {
	}
	y = y[offset:]

	xl := byte(len(x)) + x[0]>>7
	yl := byte(len(y)) + y[0]>>7
	xy := xl + yl

	out := make([]byte, 6+xy)
	out[0] = 0x30
	out[1] = xy + 4
	out[2] = 0x02
	out[3] = xl

	copy(out[(x[0]>>7)+4:], x)
	out[4+xl] = 0x02
	out[5+xl] = yl
	copy(out[(y[0]>>7)+6+xl:], y)
	return out
}

func unMarshal(in []byte) (x []byte, y []byte) {
	defer func() {
		e := recover()
		if e != nil {
			x, y = nil, nil
		}
	}()
	xl := in[3]
	x, y = in[4:4+xl], in[6+xl:]
	offset := 0
	for ; x[offset] == 0; offset++ {
	}
	x = x[offset:]
	offset = 0
	for ; y[offset] == 0; offset++ {
	}
	y = y[offset:]

	return x, y
}

func MarshalSig(x, y []byte) []byte {
	return marshal(x, y)
}

func Unmarshal(in []byte) ([]byte, []byte) {
	return unMarshal(in)
}
