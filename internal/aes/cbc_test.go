package aes

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"bandr.me/p/pocryp/internal/testutil"
)

// Based on NIST SP 800-38A
func TestCBC(t *testing.T) {
	type TestVector struct {
		key         []byte
		ciphertexts [][]byte
	}
	blocks := [][]byte{
		testutil.BytesFromHex(t, "6bc1bee22e409f96e93d7e117393172a"),
		testutil.BytesFromHex(t, "ae2d8a571e03ac9c9eb76fac45af8e51"),
		testutil.BytesFromHex(t, "30c81c46a35ce411e5fbc1191a0a52ef"),
		testutil.BytesFromHex(t, "f69f2445df4f9b17ad2b417be66c3710"),
	}
	iv := testutil.BytesFromHex(t, "000102030405060708090a0b0c0d0e0f")
	tvectors := map[string]TestVector{
		"128": TestVector{
			key: testutil.BytesFromHex(t, "2b7e151628aed2a6abf7158809cf4f3c"),
			ciphertexts: [][]byte{
				testutil.BytesFromHex(t, "7649abac8119b246cee98e9b12e9197d"),
				testutil.BytesFromHex(t, "5086cb9b507219ee95db113a917678b2"),
				testutil.BytesFromHex(t, "73bed6b8e3c1743b7116e69e22229516"),
				testutil.BytesFromHex(t, "3ff1caa1681fac09120eca307586e1a7"),
			},
		},
		"192": TestVector{
			key: testutil.BytesFromHex(t, "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
			ciphertexts: [][]byte{
				testutil.BytesFromHex(t, "4f021db243bc633d7178183a9fa071e8"),
				testutil.BytesFromHex(t, "b4d9ada9ad7dedf4e5e738763f69145a"),
				testutil.BytesFromHex(t, "571b242012fb7ae07fa9baac3df102e0"),
				testutil.BytesFromHex(t, "08b0e27988598881d920a9e64f5615cd"),
			},
		},
		"256": TestVector{
			key: testutil.BytesFromHex(t, "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
			ciphertexts: [][]byte{
				testutil.BytesFromHex(t, "f58c4c04d6e5f1ba779eabfb5f7bfbd6"),
				testutil.BytesFromHex(t, "9cfc4e967edb808d679f777bc6702c7d"),
				testutil.BytesFromHex(t, "39f23369a9d9bacfa530e26304231461"),
				testutil.BytesFromHex(t, "b2eb05e2c39be9fcda6c19078c6a9d1b"),
			},
		},
	}
	for tname, tvector := range tvectors {
		enc, err := NewCBCEncrypter(tvector.key, iv)
		if err != nil {
			t.Fatal(err)
		}
		for i, in := range blocks {
			t.Run(fmt.Sprintf("%s-Encrypt-%d", tname, i), func(t *testing.T) {
				out := CBCProcessBlocks(enc, in)
				if !bytes.Equal(out, tvector.ciphertexts[i]) {
					t.Log(hex.EncodeToString(tvector.ciphertexts[i]))
					t.Log(hex.EncodeToString(out))
					t.Fatal("not equal")
				}
			})
		}
		dec, err := NewCBCDecrypter(tvector.key, iv)
		if err != nil {
			t.Fatal(err)
		}
		for i, in := range tvector.ciphertexts {
			t.Run(fmt.Sprintf("%s-Decrypt-%d", tname, i), func(t *testing.T) {
				out := CBCProcessBlocks(dec, in)
				if !bytes.Equal(out, blocks[i]) {
					t.Log(hex.EncodeToString(blocks[i]))
					t.Log(hex.EncodeToString(out))
					t.Fatal("not equal")
				}
			})
		}
	}
}

func TestCBCMultiBlock(t *testing.T) {
	message := testutil.BytesFromHex(t, "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
	iv := testutil.BytesFromHex(t, "000102030405060708090a0b0c0d0e0f")
	key := testutil.BytesFromHex(t, "2b7e151628aed2a6abf7158809cf4f3c")
	ciphertext := testutil.BytesFromHex(t, "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7")
	t.Run("Encrypt", func(t *testing.T) {
		enc, err := NewCBCEncrypter(key, iv)
		if err != nil {
			t.Fatal(err)
		}
		out := CBCProcessBlocks(enc, message)
		if !bytes.Equal(out, ciphertext) {
			t.Log(hex.EncodeToString(ciphertext))
			t.Log(hex.EncodeToString(out))
			t.Fatal("not equal")
		}
	})
	t.Run("Decrypt", func(t *testing.T) {
		dec, err := NewCBCDecrypter(key, iv)
		if err != nil {
			t.Fatal(err)
		}
		out := CBCProcessBlocks(dec, ciphertext)
		if !bytes.Equal(out, message) {
			t.Log(hex.EncodeToString(message))
			t.Log(hex.EncodeToString(out))
			t.Fatal("not equal")
		}
	})
}
