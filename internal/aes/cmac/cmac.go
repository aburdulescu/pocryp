package cmac

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
)

const bs = 16

func Generate(key, msg []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aligned := len(msg)%bs == 0

	n := (len(msg) + 15) / bs

	if n == 0 {
		n = 1
		aligned = false
	}

	var k1, k2 [bs]byte

	generateSubKey(c, k1[:], k2[:])

	var mLast [bs]byte
	if aligned {
		copy(mLast[:], msg[(n-1)*16:])
		xor(mLast[:], k1[:])
	} else {
		pad(mLast[:], msg[(n-1)*16:])
		xor(mLast[:], k2[:])
	}

	var x [bs]byte

	for i := 0; i < n-1; i++ {
		mi := msg[i*16 : (i+1)*bs]
		xor(x[:], mi)
		c.Encrypt(x[:], x[:])
	}

	xor(mLast[:], x[:])
	c.Encrypt(mLast[:], mLast[:])

	return mLast[:], nil
}

func Verify(key, msg, mac []byte) bool {
	myMac, err := Generate(key, msg)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(mac, myMac) == 1
}

func generateSubKey(c cipher.Block, k1, k2 []byte) {
	var constRb = [bs]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x87}

	var l [bs]byte

	c.Encrypt(l[:], l[:])

	shift(k1, l[:])

	if l[0]&0x80 != 0 {
		xor(k1, constRb[:])
	}

	shift(k2, k1)

	if k1[0]&0x80 != 0 {
		xor(k2, constRb[:])
	}

}

func shift(dst, src []byte) {
	overflow := false
	for i := len(src) - 1; i >= 0; i-- {
		dst[i] = src[i] << 1
		if overflow {
			dst[i] |= 1
		}
		overflow = src[i]&0x80 != 0
	}
}

func pad(dst, src []byte) {
	copy(dst, src)
	dst[len(src)] = 0x80
}

func xor(dst, src []byte) {
	for i, v := range src {
		dst[i] ^= v
	}
}
