package aes

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"testing"

	"bandr.me/p/pocryp/internal/testutil"
)

func TestCbcCmd(t *testing.T) {
	tmp := t.TempDir()
	for name, tv := range CBCTestVectors {
		var plaintext []byte
		for _, block := range AesBlocks {
			plaintext = append(plaintext, block...)
		}
		var ciphertext []byte
		for _, ct := range tv.Ciphertexts {
			ciphertext = append(ciphertext, ct...)
		}
		t.Run("Encrypt-"+name, func(t *testing.T) {
			testCbcCmd(t, tmp, "-e", tv.Key, CBCIv, plaintext, ciphertext)
		})
		t.Run("Decrypt-"+name, func(t *testing.T) {
			testCbcCmd(t, tmp, "-d", tv.Key, CBCIv, ciphertext, plaintext)
		})
		t.Run("Default-"+name, func(t *testing.T) {
			testCbcCmd(t, tmp, "", tv.Key, CBCIv, plaintext, ciphertext)
		})
	}
	t.Run("NoKey", func(t *testing.T) {
		if err := CbcCmd(nil); err == nil {
			t.Fatal("expected and error")
		}
	})
	t.Run("KeyAsHexAndFromFile", func(t *testing.T) {
		if err := CbcCmd([]string{"-key=0011", "-key-file=foo"}); err == nil {
			t.Fatal("expected and error")
		}
	})
	t.Run("NoIv", func(t *testing.T) {
		if err := CbcCmd([]string{"-key=0011"}); err == nil {
			t.Fatal("expected and error")
		}
	})
}

func testCbcCmd(t *testing.T, tmp string, direction string, key, iv, input, expected []byte) {
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
	if err := CbcCmd(args); err != nil {
		t.Fatal(err)
	}
	testutil.ExpectFileContent(t, out, expected)
}

var CBCIv = bytesFromHex("000102030405060708090a0b0c0d0e0f")

var CBCTestVectors = map[string]AesTestVector{
	"128": {
		Key: bytesFromHex("2b7e151628aed2a6abf7158809cf4f3c"),
		Ciphertexts: [][]byte{
			bytesFromHex("7649abac8119b246cee98e9b12e9197d"),
			bytesFromHex("5086cb9b507219ee95db113a917678b2"),
			bytesFromHex("73bed6b8e3c1743b7116e69e22229516"),
			bytesFromHex("3ff1caa1681fac09120eca307586e1a7"),
		},
	},
	"192": {
		Key: bytesFromHex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
		Ciphertexts: [][]byte{
			bytesFromHex("4f021db243bc633d7178183a9fa071e8"),
			bytesFromHex("b4d9ada9ad7dedf4e5e738763f69145a"),
			bytesFromHex("571b242012fb7ae07fa9baac3df102e0"),
			bytesFromHex("08b0e27988598881d920a9e64f5615cd"),
		},
	},
	"256": {
		Key: bytesFromHex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
		Ciphertexts: [][]byte{
			bytesFromHex("f58c4c04d6e5f1ba779eabfb5f7bfbd6"),
			bytesFromHex("9cfc4e967edb808d679f777bc6702c7d"),
			bytesFromHex("39f23369a9d9bacfa530e26304231461"),
			bytesFromHex("b2eb05e2c39be9fcda6c19078c6a9d1b"),
		},
	},
}

// Based on NIST SP 800-38A
func TestCbc(t *testing.T) {
	t.Run("EncrypterInvalidKey", func(t *testing.T) {
		if _, err := newCBCEncrypter([]byte{0}, nil); err == nil {
			t.Fatal("expected and error")
		}
	})
	t.Run("DecrypterInvalidKey", func(t *testing.T) {
		if _, err := newCBCDecrypter([]byte{0}, nil); err == nil {
			t.Fatal("expected and error")
		}
	})
	for tname, tvector := range CBCTestVectors {
		enc, err := newCBCEncrypter(tvector.Key, CBCIv)
		if err != nil {
			t.Fatal(err)
		}
		for i, in := range AesBlocks {
			t.Run(fmt.Sprintf("%s-Encrypt-%d", tname, i), func(t *testing.T) {
				out := cbcProcessBlocks(enc, in)
				if !bytes.Equal(out, tvector.Ciphertexts[i]) {
					t.Log(hex.EncodeToString(tvector.Ciphertexts[i]))
					t.Log(hex.EncodeToString(out))
					t.Fatal("not equal")
				}
			})
		}
		dec, err := newCBCDecrypter(tvector.Key, CBCIv)
		if err != nil {
			t.Fatal(err)
		}
		for i, in := range tvector.Ciphertexts {
			t.Run(fmt.Sprintf("%s-Decrypt-%d", tname, i), func(t *testing.T) {
				out := cbcProcessBlocks(dec, in)
				if !bytes.Equal(out, AesBlocks[i]) {
					t.Log(hex.EncodeToString(AesBlocks[i]))
					t.Log(hex.EncodeToString(out))
					t.Fatal("not equal")
				}
			})
		}
	}
}

func TestCbcMultiBlock(t *testing.T) {
	message := bytesFromHexT(t, "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
	iv := bytesFromHexT(t, "000102030405060708090a0b0c0d0e0f")
	key := bytesFromHexT(t, "2b7e151628aed2a6abf7158809cf4f3c")
	ciphertext := bytesFromHexT(t, "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7")
	t.Run("Encrypt", func(t *testing.T) {
		enc, err := newCBCEncrypter(key, iv)
		if err != nil {
			t.Fatal(err)
		}
		out := cbcProcessBlocks(enc, message)
		if !bytes.Equal(out, ciphertext) {
			t.Log(hex.EncodeToString(ciphertext))
			t.Log(hex.EncodeToString(out))
			t.Fatal("not equal")
		}
	})
	t.Run("Decrypt", func(t *testing.T) {
		dec, err := newCBCDecrypter(key, iv)
		if err != nil {
			t.Fatal(err)
		}
		out := cbcProcessBlocks(dec, ciphertext)
		if !bytes.Equal(out, message) {
			t.Log(hex.EncodeToString(message))
			t.Log(hex.EncodeToString(out))
			t.Fatal("not equal")
		}
	})
}
