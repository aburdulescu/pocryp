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
	}
}

func testCmdAesGcm(t *testing.T, tmp string, direction string, key, nonce, aad, input, expected []byte) {
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
		"-iv", hex.EncodeToString(nonce),
		"-in", in,
		"-out", out,
	}

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
