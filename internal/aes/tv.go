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
