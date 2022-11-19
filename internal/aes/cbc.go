package aes

import (
	"crypto/aes"
	"crypto/cipher"
)

func NewCBCEncrypter(key, iv []byte) (cipher.BlockMode, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCBCEncrypter(block, iv), nil
}

func NewCBCDecrypter(key, iv []byte) (cipher.BlockMode, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCBCDecrypter(block, iv), nil
}

func CBCProcessBlocks(c cipher.BlockMode, in []byte) []byte {
	out := make([]byte, len(in))
	c.CryptBlocks(out, in)
	return out
}
