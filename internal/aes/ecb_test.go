package aes

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"bandr.me/p/pocryp/internal/testutil"
)

func TestECB(t *testing.T) {
	for tname, tvector := range ECBTestVectors {
		for i, in := range AesBlocks {
			t.Run(fmt.Sprintf("%s-Encrypt-%d", tname, i), func(t *testing.T) {
				out, err := ECB(tvector.Key, in, true)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(out, tvector.Ciphertexts[i]) {
					t.Log(hex.EncodeToString(tvector.Ciphertexts[i]))
					t.Log(hex.EncodeToString(out))
					t.Fatal("not equal")
				}
			})
		}
		for i, in := range tvector.Ciphertexts {
			t.Run(fmt.Sprintf("%s-Decrypt-%d", tname, i), func(t *testing.T) {
				out, err := ECB(tvector.Key, in, false)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(out, AesBlocks[i]) {
					t.Log(hex.EncodeToString(AesBlocks[i]))
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
