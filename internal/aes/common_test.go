package aes

import (
	"encoding/hex"
	"testing"
)

func bytesFromHexT(t testing.TB, s string) []byte {
	r, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
