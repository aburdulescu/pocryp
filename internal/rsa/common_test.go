package rsa

import (
	"os"
	"testing"
)

func readFile(t testing.TB, s string) []byte {
	r, err := os.ReadFile(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
