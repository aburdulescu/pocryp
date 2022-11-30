package rsa

import (
	"io/ioutil"
	"testing"
)

func readFile(t testing.TB, s string) []byte {
	r, err := ioutil.ReadFile(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
