package aes

import (
	"crypto/aes"
	"errors"
)

func ECB(key, in []byte, direction bool) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	if len(in)%bs != 0 {
		return nil, errors.New("need a multiple of the blocksize")
	}
	result := make([]byte, len(in))
	out := result
	for len(in) > 0 {
		if direction {
			block.Encrypt(out, in)
		} else {
			block.Decrypt(out, in)
		}
		in = in[bs:]
		out = out[bs:]
	}
	return result, nil
}
