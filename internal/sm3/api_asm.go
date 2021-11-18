//+build amd64
//+build !gmnosam

package sm3

func init() {
	update = update_32bit
}

var update func(digest *[8]uint32, a []byte, b []byte)
