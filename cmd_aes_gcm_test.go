package main

import (
	"encoding/hex"
	"io/ioutil"
	"path/filepath"
	"testing"

	poaes "bandr.me/p/pocryp/internal/aes"
)

func TestCmdAesGcm(t *testing.T) {
	tmp := t.TempDir()
	for name, tv := range poaes.GCMTestVectors {
		t.Run("Encrypt/"+name, func(t *testing.T) {
			var expected []byte
			expected = append(expected, tv.Ciphertext...)
			expected = append(expected, tv.Tag...)
			testCmdAesGcm(t, tmp, "-e", tv.Key, tv.Nonce, tv.Aad, tv.Plaintext, expected)
		})
		t.Run("Decrypt/"+name, func(t *testing.T) {
			var input []byte
			input = append(input, tv.Ciphertext...)
			input = append(input, tv.Tag...)
			testCmdAesGcm(t, tmp, "-d", tv.Key, tv.Nonce, tv.Aad, input, tv.Plaintext)
		})
		t.Run("Default/"+name, func(t *testing.T) {
			var expected []byte
			expected = append(expected, tv.Ciphertext...)
			expected = append(expected, tv.Tag...)
			testCmdAesGcm(t, tmp, "", tv.Key, tv.Nonce, tv.Aad, tv.Plaintext, expected)
		})
	}
	t.Run("NoKey", func(t *testing.T) {
		if err := cmdAesGcm(nil); err == nil {
			t.Fatal("expected and error")
		}
	})
	t.Run("KeyAsHexAndFromFile", func(t *testing.T) {
		if err := cmdAesGcm([]string{"-key=0011", "-key-file=foo"}); err == nil {
			t.Fatal("expected and error")
		}
	})
	t.Run("NoIv", func(t *testing.T) {
		if err := cmdAesGcm([]string{"-key=0011"}); err == nil {
			t.Fatal("expected and error")
		}
	})
}

func testCmdAesGcm(t *testing.T, tmp string, direction string, key, nonce, aad, input, expected []byte) {
	out := filepath.Join(tmp, "out")
	in := filepath.Join(tmp, "in")
	setupInsAndOuts(t, in, out, input)
	var args []string
	if direction != "" {
		args = append(args, direction)
	}
	args = append(args,
		"-key", hex.EncodeToString(key),
		"-iv", hex.EncodeToString(nonce),
		"-in", in,
		"-out", out,
	)
	if aad != nil {
		dstpath := filepath.Join(tmp, "aad")
		if err := ioutil.WriteFile(dstpath, aad, 0666); err != nil {
			t.Fatal(err)
		}
		args = append(args, "-aad", dstpath)
	}
	if err := cmdAesGcm(args); err != nil {
		t.Fatal(err)
	}
	expectFileContent(t, out, expected)
}
