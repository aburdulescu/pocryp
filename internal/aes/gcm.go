package aes

import (
	"crypto/aes"
	"crypto/cipher"
)

func GCM(key, nonce, in, additionalData []byte, direction bool) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	c, err := cipher.NewGCMWithNonceSize(block, len(nonce))
	if err != nil {
		return nil, err
	}
	if direction {
		return c.Seal(nil, nonce, in, additionalData), nil
	}
	return c.Open(nil, nonce, in, additionalData)
}
