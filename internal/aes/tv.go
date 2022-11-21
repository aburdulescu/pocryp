package aes

import (
	"encoding/hex"
)

func bytesFromHex(s string) []byte {
	r, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return r
}

type GCMTestVector struct {
	Key        []byte
	Nonce      []byte
	Plaintext  []byte
	Ciphertext []byte
	Tag        []byte
	Aad        []byte
}

// from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip
var GCMTestVectors = map[string]GCMTestVector{
	"key128/nonce96/without_aad": GCMTestVector{
		Key:        bytesFromHex("7fddb57453c241d03efbed3ac44e371c"),
		Nonce:      bytesFromHex("ee283a3fc75575e33efd4887"),
		Plaintext:  bytesFromHex("d5de42b461646c255c87bd2962d3b9a2"),
		Ciphertext: bytesFromHex("2ccda4a5415cb91e135c2a0f78c9b2fd"),
		Tag:        bytesFromHex("b36d1df9b9d5e596f83e8b7f52971cb3"),
	},
	"key128/nonce1024/with_aad": GCMTestVector{
		Key:        bytesFromHex("bc30eb76f5b063fdf1c4f9bb0bd38deb"),
		Nonce:      bytesFromHex("a8a578769a68b6525b5f969748b4f58fd213f375402b2f0c43f6b00f0fc598853fca52ec8f8b7ea73763f7e4c1a40741ea3d3464545416c9dd4f71755b05b154eef788ec37e2ca76fa8418841503db08763d3d04a12d7e85c3abc099729c84cb94aeac88c3e432cb8675683edf023edd707aca385bfb55d5ccc4840cbac6f12e"),
		Plaintext:  bytesFromHex("aedecddda15d1c84da2968ba351b5e5e"),
		Ciphertext: bytesFromHex("1810958e6ffb802ac40fe5b471a7c85a"),
		Aad:        bytesFromHex("e6049b4c3d1c5321c1887b1040030143"),
		Tag:        bytesFromHex("d895463b97c687c621f03c31406a0305"),
	},
}

type ECBTestVector struct {
	Key         []byte
	Ciphertexts [][]byte
}

// Based on NIST SP 800-38A
var ECBBlocks = [][]byte{
	bytesFromHex("6bc1bee22e409f96e93d7e117393172a"),
	bytesFromHex("ae2d8a571e03ac9c9eb76fac45af8e51"),
	bytesFromHex("30c81c46a35ce411e5fbc1191a0a52ef"),
	bytesFromHex("f69f2445df4f9b17ad2b417be66c3710"),
}

var ECBTestVectors = map[string]ECBTestVector{
	"128": ECBTestVector{
		Key: bytesFromHex("2b7e151628aed2a6abf7158809cf4f3c"),
		Ciphertexts: [][]byte{
			bytesFromHex("3ad77bb40d7a3660a89ecaf32466ef97"),
			bytesFromHex("f5d3d58503b9699de785895a96fdbaaf"),
			bytesFromHex("43b1cd7f598ece23881b00e3ed030688"),
			bytesFromHex("7b0c785e27e8ad3f8223207104725dd4"),
		},
	},
	"192": ECBTestVector{
		Key: bytesFromHex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
		Ciphertexts: [][]byte{
			bytesFromHex("bd334f1d6e45f25ff712a214571fa5cc"),
			bytesFromHex("974104846d0ad3ad7734ecb3ecee4eef"),
			bytesFromHex("ef7afd2270e2e60adce0ba2face6444e"),
			bytesFromHex("9a4b41ba738d6c72fb16691603c18e0e"),
		},
	},
	"256": ECBTestVector{
		Key: bytesFromHex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
		Ciphertexts: [][]byte{
			bytesFromHex("f3eed1bdb5d2a03c064b5a7e3db181f8"),
			bytesFromHex("591ccb10d410ed26dc5ba74a31362870"),
			bytesFromHex("b6ed21b99ca6f4f9f153e7b1beafed1d"),
			bytesFromHex("23304b7a39f9f3ff067d8d8f9e24ecc7"),
		},
	},
}
