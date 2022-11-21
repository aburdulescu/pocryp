package aes

import (
	"bytes"
	"encoding/hex"
	"testing"

	"bandr.me/p/pocryp/internal/testutil"
)

func BenchmarkAesKeyWrap(b *testing.B) {
	kek := testutil.BytesFromHex(b, "000102030405060708090A0B0C0D0E0F")
	data := testutil.BytesFromHex(b, "00112233445566778899AABBCCDDEEFF")
	for i := 0; i < b.N; i++ {
		out, err := KeyWrap(kek, data)
		if err != nil {
			b.Fatal(err)
		}
		_, err = KeyUnwrap(kek, out)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func TestAesKeyWrap(t *testing.T) {
	for _, v := range KeyWrapTestVectors {
		t.Run(v.Name, func(t *testing.T) {
			actualCiphertext, err := KeyWrap(v.Kek, v.Plaintext)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(v.Ciphertext, actualCiphertext) {
				t.Log(hex.EncodeToString(v.Ciphertext))
				t.Log(hex.EncodeToString(actualCiphertext))
				t.Fatal("not equal")
			}
			actualPlaintext, err := KeyUnwrap(v.Kek, v.Ciphertext)
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
