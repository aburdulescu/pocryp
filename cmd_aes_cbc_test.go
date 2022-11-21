package main

import (
	"bytes"
	"encoding/hex"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	poaes "bandr.me/p/pocryp/internal/aes"
)

func TestCmdAesCbc(t *testing.T) {
	tmp := t.TempDir()
	for name, tv := range poaes.CBCTestVectors {
		var plaintext []byte
		for _, block := range poaes.AesBlocks {
			plaintext = append(plaintext, block...)
		}
		var ciphertext []byte
		for _, ct := range tv.Ciphertexts {
			ciphertext = append(ciphertext, ct...)
		}
		t.Run("Encrypt-"+name, func(t *testing.T) {
			testCmdAesCbc(t, tmp, "-e", tv.Key, poaes.CBCIv, plaintext, ciphertext)
		})
		t.Run("Decrypt-"+name, func(t *testing.T) {
			testCmdAesCbc(t, tmp, "-d", tv.Key, poaes.CBCIv, ciphertext, plaintext)
		})
	}
}

func testCmdAesCbc(t *testing.T, tmp string, direction string, key, iv, input, expected []byte) {
	out := filepath.Join(tmp, "out")
	in := filepath.Join(tmp, "in")

	if err := ioutil.WriteFile(in, input, 0666); err != nil {
		t.Fatal(err)
	}

	f, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	args := []string{
		direction,
		"-key", hex.EncodeToString(key),
		"-iv", hex.EncodeToString(iv),
		"-in", in,
		"-out", out,
	}

	if err := cmdAesCbc(args); err != nil {
		t.Fatal(err)
	}

	result, err := ioutil.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(expected, result) {
		t.Log("expected =", hex.EncodeToString(expected))
		t.Log("result   =", hex.EncodeToString(result))
		t.Fatal("not equal")
	}
}
