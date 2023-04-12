package aes

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"testing"

	"bandr.me/p/pocryp/internal/testutil"
)

func TestEcbCmd(t *testing.T) {
	tmp := t.TempDir()
	for name, tv := range ECBTestVectors {
		for i, in := range AesBlocks {
			t.Run(fmt.Sprintf("%s-Encrypt-%d", name, i), func(t *testing.T) {
				testEcbCmd(t, tmp, "-e", tv.Key, in, tv.Ciphertexts[i])
			})
		}
		for i, in := range tv.Ciphertexts {
			t.Run(fmt.Sprintf("%s-Decrypt-%d", name, i), func(t *testing.T) {
				testEcbCmd(t, tmp, "-d", tv.Key, in, AesBlocks[i])
			})
		}
		for i, in := range AesBlocks {
			t.Run(fmt.Sprintf("%s-Default-%d", name, i), func(t *testing.T) {
				testEcbCmd(t, tmp, "", tv.Key, in, tv.Ciphertexts[i])
			})
		}
	}
	t.Run("NoKey", func(t *testing.T) {
		if err := EcbCmd(); err == nil {
			t.Fatal("expected and error")
		}
	})
	t.Run("KeyAsHexAndFromFile", func(t *testing.T) {
		if err := EcbCmd("-key=0011", "-key-file=foo"); err == nil {
			t.Fatal("expected and error")
		}
	})
}

func testEcbCmd(t *testing.T, tmp string, direction string, key, input, expected []byte) {
	out := filepath.Join(tmp, "out")
	in := filepath.Join(tmp, "in")
	testutil.SetupInsAndOuts(t, in, out, input)
	var args []string
	if direction != "" {
		args = append(args, direction)
	}
	args = append(args,
		"-key", hex.EncodeToString(key),
		"-in", in,
		"-out", out,
	)
	if err := EcbCmd(args...); err != nil {
		t.Fatal(err)
	}
	testutil.ExpectFileContent(t, out, expected)
}

var ECBTestVectors = map[string]AesTestVector{
	"128": {
		Key: bytesFromHex("2b7e151628aed2a6abf7158809cf4f3c"),
		Ciphertexts: [][]byte{
			bytesFromHex("3ad77bb40d7a3660a89ecaf32466ef97"),
			bytesFromHex("f5d3d58503b9699de785895a96fdbaaf"),
			bytesFromHex("43b1cd7f598ece23881b00e3ed030688"),
			bytesFromHex("7b0c785e27e8ad3f8223207104725dd4"),
		},
	},
	"192": {
		Key: bytesFromHex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
		Ciphertexts: [][]byte{
			bytesFromHex("bd334f1d6e45f25ff712a214571fa5cc"),
			bytesFromHex("974104846d0ad3ad7734ecb3ecee4eef"),
			bytesFromHex("ef7afd2270e2e60adce0ba2face6444e"),
			bytesFromHex("9a4b41ba738d6c72fb16691603c18e0e"),
		},
	},
	"256": {
		Key: bytesFromHex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
		Ciphertexts: [][]byte{
			bytesFromHex("f3eed1bdb5d2a03c064b5a7e3db181f8"),
			bytesFromHex("591ccb10d410ed26dc5ba74a31362870"),
			bytesFromHex("b6ed21b99ca6f4f9f153e7b1beafed1d"),
			bytesFromHex("23304b7a39f9f3ff067d8d8f9e24ecc7"),
		},
	},
}

func TestEcb(t *testing.T) {
	t.Run("InvalidKey", func(t *testing.T) {
		if _, err := ecb([]byte{0}, nil, true); err == nil {
			t.Fatal("expected an error")
		}
	})
	t.Run("InvalidInput", func(t *testing.T) {
		dummyKey := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
		if _, err := ecb(dummyKey, []byte{0}, true); err == nil {
			t.Fatal("expected an error")
		}
	})
	for tname, tvector := range ECBTestVectors {
		for i, in := range AesBlocks {
			t.Run(fmt.Sprintf("%s-Encrypt-%d", tname, i), func(t *testing.T) {
				out, err := ecb(tvector.Key, in, true)
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
				out, err := ecb(tvector.Key, in, false)
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
	message := bytesFromHexT(t, "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
	key := bytesFromHexT(t, "2b7e151628aed2a6abf7158809cf4f3c")
	ciphertext := bytesFromHexT(t, "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4")
	t.Run("Encrypt", func(t *testing.T) {
		out, err := ecb(key, message, true)
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
		out, err := ecb(key, ciphertext, false)
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
