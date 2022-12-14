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
	"key128/nonce96/without_aad": {
		Key:        bytesFromHex("7fddb57453c241d03efbed3ac44e371c"),
		Nonce:      bytesFromHex("ee283a3fc75575e33efd4887"),
		Plaintext:  bytesFromHex("d5de42b461646c255c87bd2962d3b9a2"),
		Ciphertext: bytesFromHex("2ccda4a5415cb91e135c2a0f78c9b2fd"),
		Tag:        bytesFromHex("b36d1df9b9d5e596f83e8b7f52971cb3"),
	},
	"key128/nonce1024/with_aad": {
		Key:        bytesFromHex("bc30eb76f5b063fdf1c4f9bb0bd38deb"),
		Nonce:      bytesFromHex("a8a578769a68b6525b5f969748b4f58fd213f375402b2f0c43f6b00f0fc598853fca52ec8f8b7ea73763f7e4c1a40741ea3d3464545416c9dd4f71755b05b154eef788ec37e2ca76fa8418841503db08763d3d04a12d7e85c3abc099729c84cb94aeac88c3e432cb8675683edf023edd707aca385bfb55d5ccc4840cbac6f12e"),
		Plaintext:  bytesFromHex("aedecddda15d1c84da2968ba351b5e5e"),
		Ciphertext: bytesFromHex("1810958e6ffb802ac40fe5b471a7c85a"),
		Aad:        bytesFromHex("e6049b4c3d1c5321c1887b1040030143"),
		Tag:        bytesFromHex("d895463b97c687c621f03c31406a0305"),
	},
}

type AesTestVector struct {
	Key         []byte
	Ciphertexts [][]byte
}

// Based on NIST SP 800-38A
var AesBlocks = [][]byte{
	bytesFromHex("6bc1bee22e409f96e93d7e117393172a"),
	bytesFromHex("ae2d8a571e03ac9c9eb76fac45af8e51"),
	bytesFromHex("30c81c46a35ce411e5fbc1191a0a52ef"),
	bytesFromHex("f69f2445df4f9b17ad2b417be66c3710"),
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

var CBCIv = bytesFromHex("000102030405060708090a0b0c0d0e0f")

var CBCTestVectors = map[string]AesTestVector{
	"128": {
		Key: bytesFromHex("2b7e151628aed2a6abf7158809cf4f3c"),
		Ciphertexts: [][]byte{
			bytesFromHex("7649abac8119b246cee98e9b12e9197d"),
			bytesFromHex("5086cb9b507219ee95db113a917678b2"),
			bytesFromHex("73bed6b8e3c1743b7116e69e22229516"),
			bytesFromHex("3ff1caa1681fac09120eca307586e1a7"),
		},
	},
	"192": {
		Key: bytesFromHex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
		Ciphertexts: [][]byte{
			bytesFromHex("4f021db243bc633d7178183a9fa071e8"),
			bytesFromHex("b4d9ada9ad7dedf4e5e738763f69145a"),
			bytesFromHex("571b242012fb7ae07fa9baac3df102e0"),
			bytesFromHex("08b0e27988598881d920a9e64f5615cd"),
		},
	},
	"256": {
		Key: bytesFromHex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
		Ciphertexts: [][]byte{
			bytesFromHex("f58c4c04d6e5f1ba779eabfb5f7bfbd6"),
			bytesFromHex("9cfc4e967edb808d679f777bc6702c7d"),
			bytesFromHex("39f23369a9d9bacfa530e26304231461"),
			bytesFromHex("b2eb05e2c39be9fcda6c19078c6a9d1b"),
		},
	},
}

type KeyWrapTestVector struct {
	Name       string
	Kek        []byte
	Plaintext  []byte
	Ciphertext []byte
}

// based on RFC3394
var KeyWrapTestVectors = []KeyWrapTestVector{
	{
		Name:       "4.1-128DataWith128KEK",
		Kek:        bytesFromHex("000102030405060708090A0B0C0D0E0F"),
		Plaintext:  bytesFromHex("00112233445566778899AABBCCDDEEFF"),
		Ciphertext: bytesFromHex("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5"),
	},
	{
		Name:       "4.2-128DataWith192KEK",
		Kek:        bytesFromHex("000102030405060708090A0B0C0D0E0F1011121314151617"),
		Plaintext:  bytesFromHex("00112233445566778899AABBCCDDEEFF"),
		Ciphertext: bytesFromHex("96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D"),
	},
	{
		Name:       "4.3-128DataWith256KEK",
		Kek:        bytesFromHex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
		Plaintext:  bytesFromHex("00112233445566778899AABBCCDDEEFF"),
		Ciphertext: bytesFromHex("64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7"),
	},
	{
		Name:       "4.4-192DataWith192KEK",
		Kek:        bytesFromHex("000102030405060708090A0B0C0D0E0F1011121314151617"),
		Plaintext:  bytesFromHex("00112233445566778899AABBCCDDEEFF0001020304050607"),
		Ciphertext: bytesFromHex("031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2"),
	},
	{
		Name:       "4.5-192DataWith256KEK",
		Kek:        bytesFromHex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
		Plaintext:  bytesFromHex("00112233445566778899AABBCCDDEEFF0001020304050607"),
		Ciphertext: bytesFromHex("A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1"),
	},
	{
		Name:       "4.6-256DataWith256KEK",
		Kek:        bytesFromHex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
		Plaintext:  bytesFromHex("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F"),
		Ciphertext: bytesFromHex("28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21"),
	},
}
