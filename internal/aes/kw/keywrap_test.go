package kw

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func BenchmarkAesKeyWrap(b *testing.B) {
	kek := bytesFromHexT(b, "000102030405060708090A0B0C0D0E0F")
	data := bytesFromHexT(b, "00112233445566778899AABBCCDDEEFF")
	for i := 0; i < b.N; i++ {
		out, err := Wrap(kek, data)
		if err != nil {
			b.Fatal(err)
		}
		_, err = Unwrap(kek, out)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func TestKeyWrap(t *testing.T) {
	t.Run("WrapInvalidPlaintext", func(t *testing.T) {
		if _, err := Wrap(nil, []byte{0}); err == nil {
			t.Fatal("expected and error")
		}
	})
	t.Run("WrapInvalidKey", func(t *testing.T) {
		plaintext := []byte{0, 1, 2, 3, 4, 5, 6, 7}
		if _, err := Wrap([]byte{0}, plaintext); err == nil {
			t.Fatal("expected and error")
		}
	})
	t.Run("UnwrapInvalidKey", func(t *testing.T) {
		plaintext := []byte{0, 1, 2, 3, 4, 5, 6, 7}
		if _, err := Unwrap([]byte{0}, plaintext); err == nil {
			t.Fatal("expected and error")
		}
	})
	for _, v := range TestVectors {
		t.Run(v.Name, func(t *testing.T) {
			actualCiphertext, err := Wrap(v.Kek, v.Plaintext)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(v.Ciphertext, actualCiphertext) {
				t.Log(hex.EncodeToString(v.Ciphertext))
				t.Log(hex.EncodeToString(actualCiphertext))
				t.Fatal("not equal")
			}
			actualPlaintext, err := Unwrap(v.Kek, v.Ciphertext)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(v.Plaintext, actualPlaintext) {
				t.Log(hex.EncodeToString(v.Plaintext))
				t.Log(hex.EncodeToString(actualPlaintext))
				t.Fatal("not equal")
			}
		})
	}
}

func bytesFromHexT(t testing.TB, s string) []byte {
	t.Helper()
	r, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return r
}
