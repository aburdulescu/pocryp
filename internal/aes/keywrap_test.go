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
	type testCase struct {
		Name       string
		Kek        string
		Plaintext  string
		Ciphertext string
	}
	vectors := []testCase{
		{
			Name:       "4.1-128DataWith128KEK",
			Kek:        "000102030405060708090A0B0C0D0E0F",
			Plaintext:  "00112233445566778899AABBCCDDEEFF",
			Ciphertext: "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5",
		},
		{
			Name:       "4.2-128DataWith192KEK",
			Kek:        "000102030405060708090A0B0C0D0E0F1011121314151617",
			Plaintext:  "00112233445566778899AABBCCDDEEFF",
			Ciphertext: "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D",
		},
		{
			Name:       "4.3-128DataWith256KEK",
			Kek:        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
			Plaintext:  "00112233445566778899AABBCCDDEEFF",
			Ciphertext: "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7",
		},
		{
			Name:       "4.4-192DataWith192KEK",
			Kek:        "000102030405060708090A0B0C0D0E0F1011121314151617",
			Plaintext:  "00112233445566778899AABBCCDDEEFF0001020304050607",
			Ciphertext: "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2",
		},
		{
			Name:       "4.5-192DataWith256KEK",
			Kek:        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
			Plaintext:  "00112233445566778899AABBCCDDEEFF0001020304050607",
			Ciphertext: "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1",
		},
		{
			Name:       "4.6-256DataWith256KEK",
			Kek:        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
			Plaintext:  "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
			Ciphertext: "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21",
		},
	}
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			kek := testutil.BytesFromHex(t, v.Kek)
			plaintext := testutil.BytesFromHex(t, v.Plaintext)
			ciphertext := testutil.BytesFromHex(t, v.Ciphertext)
			actualCiphertext, err := KeyWrap(kek, plaintext)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(ciphertext, actualCiphertext) {
				t.Log(v.Ciphertext)
				t.Log(hex.EncodeToString(actualCiphertext))
				t.Fatal("not equal")
			}
			actualPlaintext, err := KeyUnwrap(kek, ciphertext)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(plaintext, actualPlaintext) {
				t.Log(v.Plaintext)
				t.Log(hex.EncodeToString(actualPlaintext))
				t.Fatal("not equal")
			}
		})
	}
}
