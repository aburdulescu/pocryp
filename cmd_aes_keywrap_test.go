package main

import (
	"encoding/hex"
	"path/filepath"
	"testing"

	poaes "bandr.me/p/pocryp/internal/aes"
)

func TestCmdAesKeywrap(t *testing.T) {
	tmp := t.TempDir()
	for _, tv := range poaes.KeyWrapTestVectors {
		t.Run("Wrap-"+tv.Name, func(t *testing.T) {
			testCmdAesKeywrap(t, tmp, "-w", tv.Kek, tv.Plaintext, tv.Ciphertext)
		})
		t.Run("Unwrap-"+tv.Name, func(t *testing.T) {
			testCmdAesKeywrap(t, tmp, "-u", tv.Kek, tv.Ciphertext, tv.Plaintext)
		})
	}
}

func testCmdAesKeywrap(t *testing.T, tmp string, direction string, key, input, expected []byte) {
	out := filepath.Join(tmp, "out")
	in := filepath.Join(tmp, "in")
	setupInsAndOuts(t, in, out, input)
	args := []string{
		direction,
		"-key", hex.EncodeToString(key),
		"-in", in,
		"-out", out,
	}
	if err := cmdAesKeywrap(args); err != nil {
		t.Fatal(err)
	}
	expectFileContent(t, out, expected)
}
