package mp

import (
	"crypto/aes"
	"errors"
)

const bs = 16

func Compress(srcKey, constant []byte) ([]byte, error) {
	if len(srcKey)%bs != 0 {
		return nil, errors.New("srckey not aligned to AES block")
	}
	if len(constant)%bs != 0 {
		return nil, errors.New("constant not aligned to AES block")
	}
	paddedConstant := constant
	if len(srcKey) > len(constant) {
		paddedConstant = padd(constant, len(srcKey)-len(constant))
	}
	h0 := make([]byte, len(srcKey))
	out0 := encrypt(h0, srcKey)
	h1 := xor3(out0, srcKey, h0)
	out1 := encrypt(h1, paddedConstant)
	return xor3(out1, paddedConstant, h1), nil
}

func padd(in []byte, n int) []byte {
	r := make([]byte, 0, len(in)+n)
	r = append(r, in...)
	return append(r, make([]byte, n)...)
}

func encrypt(key, in []byte) []byte {
	c, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	out := make([]byte, len(in))
	c.Encrypt(out, in)
	return out
}

func xor3(b0, b1, b2 []byte) []byte {
	if len(b0) != len(b1) {
		panic("inputs with different lengths")
	}
	if len(b0) != len(b2) {
		panic("inputs with different lengths")
	}
	res := make([]byte, len(b0))
	for i := range b0 {
		res[i] = b0[i] ^ b1[i] ^ b2[i]
	}
	return res
}
