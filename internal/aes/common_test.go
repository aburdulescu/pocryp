package aes

import (
	"encoding/hex"
	"testing"
)

type AesTestVector struct {
	Key         []byte
	Ciphertexts [][]byte
}

// Based on NIST SP 800-38A
var AesBlocks = [][]byte{
	bytesFromHex("6bc1bee22e409f96e93d7e117393172a"),
	bytesFromHex("ae2d8a571e03ac9c9eb76fac45af8e51"),
	bytesFromHex("30c81c46a35ce411e5fbc1191a0a52ef"),
	bytesFromHex("f69f2445df4f9b17ad2b417be66c3710"),
}

func bytesFromHex(s string) []byte {
	r, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return r
}

func bytesFromHexT(t testing.TB, s string) []byte {
	t.Helper()
	r, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return r
}
