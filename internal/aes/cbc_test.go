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
	t.Run("EncrypterInvalidKey", func(t *testing.T) {
		if _, err := NewCBCEncrypter([]byte{0}, nil); err == nil {
			t.Fatal("expected and error")
		}
	})
	t.Run("DecrypterInvalidKey", func(t *testing.T) {
		if _, err := NewCBCDecrypter([]byte{0}, nil); err == nil {
			t.Fatal("expected and error")
		}
	})
	for tname, tvector := range CBCTestVectors {
		enc, err := NewCBCEncrypter(tvector.Key, CBCIv)
		if err != nil {
			t.Fatal(err)
		}
		for i, in := range AesBlocks {
			t.Run(fmt.Sprintf("%s-Encrypt-%d", tname, i), func(t *testing.T) {
				out := CBCProcessBlocks(enc, in)
				if !bytes.Equal(out, tvector.Ciphertexts[i]) {
					t.Log(hex.EncodeToString(tvector.Ciphertexts[i]))
					t.Log(hex.EncodeToString(out))
					t.Fatal("not equal")
				}
			})
		}
		dec, err := NewCBCDecrypter(tvector.Key, CBCIv)
		if err != nil {
			t.Fatal(err)
		}
		for i, in := range tvector.Ciphertexts {
			t.Run(fmt.Sprintf("%s-Decrypt-%d", tname, i), func(t *testing.T) {
				out := CBCProcessBlocks(dec, in)
				if !bytes.Equal(out, AesBlocks[i]) {
					t.Log(hex.EncodeToString(AesBlocks[i]))
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
