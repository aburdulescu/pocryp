package aes

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"bandr.me/p/pocryp/internal/testutil"
)

// Based on NIST SP 800-38A
func TestECB(t *testing.T) {
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
	tvectors := map[string]TestVector{
		"128": TestVector{
			key: testutil.BytesFromHex(t, "2b7e151628aed2a6abf7158809cf4f3c"),
			ciphertexts: [][]byte{
				testutil.BytesFromHex(t, "3ad77bb40d7a3660a89ecaf32466ef97"),
				testutil.BytesFromHex(t, "f5d3d58503b9699de785895a96fdbaaf"),
				testutil.BytesFromHex(t, "43b1cd7f598ece23881b00e3ed030688"),
				testutil.BytesFromHex(t, "7b0c785e27e8ad3f8223207104725dd4"),
			},
		},
		"192": TestVector{
			key: testutil.BytesFromHex(t, "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
			ciphertexts: [][]byte{
				testutil.BytesFromHex(t, "bd334f1d6e45f25ff712a214571fa5cc"),
				testutil.BytesFromHex(t, "974104846d0ad3ad7734ecb3ecee4eef"),
				testutil.BytesFromHex(t, "ef7afd2270e2e60adce0ba2face6444e"),
				testutil.BytesFromHex(t, "9a4b41ba738d6c72fb16691603c18e0e"),
			},
		},
		"256": TestVector{
			key: testutil.BytesFromHex(t, "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
			ciphertexts: [][]byte{
				testutil.BytesFromHex(t, "f3eed1bdb5d2a03c064b5a7e3db181f8"),
				testutil.BytesFromHex(t, "591ccb10d410ed26dc5ba74a31362870"),
				testutil.BytesFromHex(t, "b6ed21b99ca6f4f9f153e7b1beafed1d"),
				testutil.BytesFromHex(t, "23304b7a39f9f3ff067d8d8f9e24ecc7"),
			},
		},
	}
	for tname, tvector := range tvectors {
		for i, in := range blocks {
			t.Run(fmt.Sprintf("%s-Encrypt-%d", tname, i), func(t *testing.T) {
				out, err := ECB(tvector.key, in, true)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(out, tvector.ciphertexts[i]) {
					t.Log(hex.EncodeToString(tvector.ciphertexts[i]))
					t.Log(hex.EncodeToString(out))
					t.Fatal("not equal")
				}
			})
		}
		for i, in := range tvector.ciphertexts {
			t.Run(fmt.Sprintf("%s-Decrypt-%d", tname, i), func(t *testing.T) {
				out, err := ECB(tvector.key, in, false)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(out, blocks[i]) {
					t.Log(hex.EncodeToString(blocks[i]))
					t.Log(hex.EncodeToString(out))
					t.Fatal("not equal")
				}
			})
		}
	}
}

func TestECBMultiBlock(t *testing.T) {
	message := testutil.BytesFromHex(t, "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
	key := testutil.BytesFromHex(t, "2b7e151628aed2a6abf7158809cf4f3c")
	ciphertext := testutil.BytesFromHex(t, "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4")
	t.Run("Encrypt", func(t *testing.T) {
		out, err := ECB(key, message, true)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out, ciphertext) {
			t.Log(hex.EncodeToString(ciphertext))
			t.Log(hex.EncodeToString(out))
			t.Fatal("not equal")
		}
	})
	t.Run("Decrypt", func(t *testing.T) {
		out, err := ECB(key, ciphertext, false)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out, message) {
			t.Log(hex.EncodeToString(message))
			t.Log(hex.EncodeToString(out))
			t.Fatal("not equal")
		}
	})
}
