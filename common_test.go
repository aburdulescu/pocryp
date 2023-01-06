package main

import (
	"bytes"
	"encoding/hex"
	"os"
	"testing"
)

func setupInsAndOuts(t *testing.T, in, out string, input []byte) {
	if err := os.WriteFile(in, input, 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
}

func expectFileContent(t *testing.T, file string, expected []byte) {
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
