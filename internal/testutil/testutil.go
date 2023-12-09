package testutil

import (
	"bytes"
	"encoding/hex"
	"os"
	"testing"
)

func SetupInOut(t *testing.T, in, out string, input []byte) {
	t.Helper()
	if err := os.WriteFile(in, input, 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
}

func ExpectFileContent(t *testing.T, file string, expected []byte) {
	t.Helper()
	result, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(expected, result) {
		t.Log("expected =", hex.EncodeToString(expected))
		t.Log("result   =", hex.EncodeToString(result))
		t.Fatal("not equal")
	}
}

func ExpectFileContentHex(t *testing.T, file string, expected string) {
	t.Helper()
	ExpectFileContent(t, file, BytesFromHex(t, expected))
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
