package aes

import (
	"crypto/aes"
	"crypto/cipher"
)

func GCMEncypt(key, nonce, in []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	c, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return c.Seal(nil, nonce, in, nil), nil
}
