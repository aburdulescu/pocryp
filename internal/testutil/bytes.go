package testutil

import (
	"encoding/hex"
	"io/ioutil"
	"testing"
)

func BytesFromHex(t testing.TB, s string) []byte {
	r, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func ReadFile(t testing.TB, s string) []byte {
	r, err := ioutil.ReadFile(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
