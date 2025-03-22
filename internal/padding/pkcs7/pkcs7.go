package pkcs7

import (
	"bytes"
	"crypto/subtle"
	"errors"
)

func Pad(blockSize byte, input []byte) []byte {
	if blockSize == 0 {
		panic("blockSize cannot be 0")
	}
	paddingByte := int(blockSize) - len(input)%int(blockSize)
	padding := bytes.Repeat([]byte{byte(paddingByte)}, paddingByte)
	return append(input, padding...)
}

func Unpad(blockSize byte, input []byte) ([]byte, error) {
	if len(input) == 0 {
		return input, nil
	}
	paddingByte := int(input[len(input)-1])
	if byte(paddingByte) > blockSize || paddingByte > len(input) {
		return nil, errors.New("invalid padding: out of block size range")
	}
	expectedPadding := bytes.Repeat([]byte{byte(paddingByte)}, paddingByte)
	paddingToCheck := input[len(input)-paddingByte:]
	if subtle.ConstantTimeCompare(paddingToCheck, expectedPadding) == 0 {
		return nil, errors.New("invalid padding: padding bytes not equal")
	}
	return input[:len(input)-paddingByte], nil
}
