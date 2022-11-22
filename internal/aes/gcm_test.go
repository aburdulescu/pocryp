package aes

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestGCM(t *testing.T) {
	t.Run("InvalidKey", func(t *testing.T) {
		if _, err := GCM([]byte{0}, nil, nil, nil, true); err == nil {
			t.Fatal("expected and error")
		}
	})
	t.Run("InvalidNonce", func(t *testing.T) {
		dummyKey := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
		if _, err := GCM(dummyKey, nil, nil, nil, true); err == nil {
			t.Fatal("expected and error")
		}
	})
	for name, tv := range GCMTestVectors {
		t.Run("Encrypt/"+name, func(t *testing.T) {
			out, err := GCM(tv.Key, tv.Nonce, tv.Plaintext, tv.Aad, true)
			if err != nil {
				t.Fatal(err)
			}
			var expectedOut []byte
			expectedOut = append(expectedOut, tv.Ciphertext...)
			expectedOut = append(expectedOut, tv.Tag...)
			if !bytes.Equal(out, expectedOut) {
				t.Log(hex.EncodeToString(expectedOut))
				t.Log(hex.EncodeToString(out))
				t.Fatal("not equal")
			}
		})

		t.Run("Decrypt/"+name, func(t *testing.T) {
			var in []byte
			in = append(in, tv.Ciphertext...)
			in = append(in, tv.Tag...)
			out, err := GCM(tv.Key, tv.Nonce, in, tv.Aad, false)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(out, tv.Plaintext) {
				t.Log(hex.EncodeToString(tv.Plaintext))
				t.Log(hex.EncodeToString(out))
				t.Fatal("not equal")
			}
		})
	}
}
