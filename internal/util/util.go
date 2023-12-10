package util

import (
	"encoding/hex"
	"errors"
	"os"
)

func BitLenToByteLen(n int) int {
	return (n + 7) / 8
}

func Concat(dst, l, r []byte) error {
	if len(dst) < (len(l) + len(r)) {
		return errors.New("xor: destination is too small")
	}
	copy(dst, l)
	copy(dst[len(l):], r)
	return nil
}

func Xor(dst, l, r []byte) error {
	if len(l) != len(r) {
		return errors.New("xor: operands with different lengths")
	}
	if len(dst) != len(l) {
		return errors.New("xor: destination of different length")
	}
	for i := range l {
		dst[i] = l[i] ^ r[i]
	}
	return nil
}

func FileOrHex(filePath, hexStr string) ([]byte, error) {
	if filePath == "" && hexStr == "" {
		return nil, errors.New("neither file path nor hex string specified")
	}
	if filePath != "" && hexStr != "" {
		return nil, errors.New("cannot specify file path and hex string at the same time")
	}
	if hexStr != "" {
		return hex.DecodeString(hexStr)
	} else {
		return os.ReadFile(filePath)
	}
}
