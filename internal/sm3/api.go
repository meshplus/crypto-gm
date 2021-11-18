//+build !amd64 gmnosam

package sm3

func update(digest *[8]uint32, a []byte, b []byte) {
	update_32bit(digest, a, b)
}
