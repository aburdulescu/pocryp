package testutil

import (
	"bytes"
	"encoding/hex"
	"os"
	"testing"
)

func SetupIn(t *testing.T, in string, input []byte) {
	t.Helper()
	if err := os.WriteFile(in, input, 0600); err != nil {
		t.Fatal(err)
	}
}

func SetupOut(t *testing.T, out string) {
	t.Helper()
	f, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
}

func SetupInOut(t *testing.T, in, out string, input []byte) {
	t.Helper()
	SetupIn(t, in, input)
	SetupOut(t, out)
}

func ExpectFileContent(t *testing.T, file string, want []byte) {
	t.Helper()
	have, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, have) {
		t.Log("want =", hex.EncodeToString(want))
		t.Log("have =", hex.EncodeToString(have))
		t.Fatal("not equal")
	}
}

func ExpectFileContentHex(t *testing.T, file string, want string) {
	t.Helper()
	ExpectFileContent(t, file, BytesFromHex(t, want))
}

func BytesFromHex(t testing.TB, s string) []byte {
	t.Helper()
	r, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func ReadFile(t testing.TB, s string) []byte {
	t.Helper()
	r, err := os.ReadFile(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
