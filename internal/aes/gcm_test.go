package aes

import (
	"bytes"
	"encoding/hex"
	"testing"

	"bandr.me/p/pocryp/internal/testutil"
)

func TestGCM(t *testing.T) {
	type testvector struct {
		key        []byte
		nonce      []byte
		plaintext  []byte
		ciphertext []byte
		tag        []byte
		aad        []byte
	}

	tvs := map[string]testvector{
		"key128/nonce96/without_aad": testvector{
			key:        testutil.BytesFromHex(t, "7fddb57453c241d03efbed3ac44e371c"),
			nonce:      testutil.BytesFromHex(t, "ee283a3fc75575e33efd4887"),
			plaintext:  testutil.BytesFromHex(t, "d5de42b461646c255c87bd2962d3b9a2"),
			ciphertext: testutil.BytesFromHex(t, "2ccda4a5415cb91e135c2a0f78c9b2fd"),
			tag:        testutil.BytesFromHex(t, "b36d1df9b9d5e596f83e8b7f52971cb3"),
		},
		"key128/nonce1024/with_aad": testvector{
			key:        testutil.BytesFromHex(t, "bc30eb76f5b063fdf1c4f9bb0bd38deb"),
			nonce:      testutil.BytesFromHex(t, "a8a578769a68b6525b5f969748b4f58fd213f375402b2f0c43f6b00f0fc598853fca52ec8f8b7ea73763f7e4c1a40741ea3d3464545416c9dd4f71755b05b154eef788ec37e2ca76fa8418841503db08763d3d04a12d7e85c3abc099729c84cb94aeac88c3e432cb8675683edf023edd707aca385bfb55d5ccc4840cbac6f12e"),
			plaintext:  testutil.BytesFromHex(t, "aedecddda15d1c84da2968ba351b5e5e"),
			ciphertext: testutil.BytesFromHex(t, "1810958e6ffb802ac40fe5b471a7c85a"),
			aad:        testutil.BytesFromHex(t, "e6049b4c3d1c5321c1887b1040030143"),
			tag:        testutil.BytesFromHex(t, "d895463b97c687c621f03c31406a0305"),
		},
	}

	for name, tv := range tvs {
		t.Run("Encrypt/"+name, func(t *testing.T) {
			out, err := GCM(tv.key, tv.nonce, tv.plaintext, tv.aad, true)
			if err != nil {
				t.Fatal(err)
			}
			var expectedOut []byte
			expectedOut = append(expectedOut, tv.ciphertext...)
			expectedOut = append(expectedOut, tv.tag...)
			if !bytes.Equal(out, expectedOut) {
				t.Log(hex.EncodeToString(expectedOut))
				t.Log(hex.EncodeToString(out))
				t.Fatal("not equal")
			}
		})

		t.Run("Decrypt/"+name, func(t *testing.T) {
			var in []byte
			in = append(in, tv.ciphertext...)
			in = append(in, tv.tag...)
			out, err := GCM(tv.key, tv.nonce, in, tv.aad, false)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(out, tv.plaintext) {
				t.Log(hex.EncodeToString(tv.plaintext))
				t.Log(hex.EncodeToString(out))
				t.Fatal("not equal")
			}
		})
	}
}
