package aes

import (
	"encoding/hex"
	"path/filepath"
	"testing"

	poaes "bandr.me/p/pocryp/internal/aes"
	"bandr.me/p/pocryp/internal/cmd/testutil"
)

func TestCbc(t *testing.T) {
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
			testCbc(t, tmp, "-e", tv.Key, poaes.CBCIv, plaintext, ciphertext)
		})
		t.Run("Decrypt-"+name, func(t *testing.T) {
			testCbc(t, tmp, "-d", tv.Key, poaes.CBCIv, ciphertext, plaintext)
		})
		t.Run("Default-"+name, func(t *testing.T) {
			testCbc(t, tmp, "", tv.Key, poaes.CBCIv, plaintext, ciphertext)
		})
	}
	t.Run("NoKey", func(t *testing.T) {
		if err := Cbc(nil); err == nil {
			t.Fatal("expected and error")
		}
	})
	t.Run("KeyAsHexAndFromFile", func(t *testing.T) {
		if err := Cbc([]string{"-key=0011", "-key-file=foo"}); err == nil {
			t.Fatal("expected and error")
		}
	})
	t.Run("NoIv", func(t *testing.T) {
		if err := Cbc([]string{"-key=0011"}); err == nil {
			t.Fatal("expected and error")
		}
	})
}

func testCbc(t *testing.T, tmp string, direction string, key, iv, input, expected []byte) {
	out := filepath.Join(tmp, "out")
	in := filepath.Join(tmp, "in")
	testutil.SetupInsAndOuts(t, in, out, input)
	var args []string
	if direction != "" {
		args = append(args, direction)
	}
	args = append(args,
		"-key", hex.EncodeToString(key),
		"-iv", hex.EncodeToString(iv),
		"-in", in,
		"-out", out,
	)
	if err := Cbc(args); err != nil {
		t.Fatal(err)
	}
	testutil.ExpectFileContent(t, out, expected)
}
