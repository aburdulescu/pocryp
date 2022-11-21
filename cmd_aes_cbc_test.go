package main

import (
	"encoding/hex"
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
	setupInsAndOuts(t, in, out, input)
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
	expectFileContent(t, out, expected)
}
