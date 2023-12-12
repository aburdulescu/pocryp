package aes

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"bandr.me/p/pocryp/internal/testutil"
)

func TestGcmCmd(t *testing.T) {
	tmp := t.TempDir()
	for name, tv := range GCMTestVectors {
		t.Run("Encrypt/"+name, func(t *testing.T) {
			var expected []byte
			expected = append(expected, tv.Ciphertext...)
			expected = append(expected, tv.Tag...)
			testGcm(t, tmp, "-e", tv.Key, tv.Nonce, tv.Aad, tv.Plaintext, expected)
		})
		t.Run("Decrypt/"+name, func(t *testing.T) {
			var input []byte
			input = append(input, tv.Ciphertext...)
			input = append(input, tv.Tag...)
			testGcm(t, tmp, "-d", tv.Key, tv.Nonce, tv.Aad, input, tv.Plaintext)
		})
		t.Run("Default/"+name, func(t *testing.T) {
			var expected []byte
			expected = append(expected, tv.Ciphertext...)
			expected = append(expected, tv.Tag...)
			testGcm(t, tmp, "", tv.Key, tv.Nonce, tv.Aad, tv.Plaintext, expected)
		})
	}
	t.Run("NoKey", func(t *testing.T) {
		if err := testutil.RunCmd(GcmCmd); err == nil {
			t.Fatal("expected and error")
		}
	})
	t.Run("KeyAsHexAndFromFile", func(t *testing.T) {
		if err := testutil.RunCmd(GcmCmd, "-key=0011", "-key-file=foo"); err == nil {
			t.Fatal("expected and error")
		}
	})
	t.Run("NoIv", func(t *testing.T) {
		if err := testutil.RunCmd(GcmCmd, "-key=0011"); err == nil {
			t.Fatal("expected and error")
		}
	})
}

func testGcm(t *testing.T, tmp string, direction string, key, nonce, aad, input, expected []byte) {
	out := filepath.Join(tmp, "out")
	in := filepath.Join(tmp, "in")
	testutil.SetupInOut(t, in, out, input)
	var args []string
	if direction != "" {
		args = append(args, direction)
	}
	args = append(args,
		"-bin",
		"-key", hex.EncodeToString(key),
		"-iv", hex.EncodeToString(nonce),
		"-in", in,
		"-out", out,
	)
	if aad != nil {
		dstpath := filepath.Join(tmp, "aad")
		if err := os.WriteFile(dstpath, aad, 0600); err != nil {
			t.Fatal(err)
		}
		args = append(args, "-aad", dstpath)
	}
	if err := testutil.RunCmd(GcmCmd, args...); err != nil {
		t.Fatal(err)
	}
	testutil.ExpectFileContent(t, out, expected)
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

func TestGcmPriv(t *testing.T) {
	t.Run("InvalidKey", func(t *testing.T) {
		if _, err := gcm([]byte{0}, nil, nil, nil, true); err == nil {
			t.Fatal("expected and error")
		}
	})
	t.Run("InvalidNonce", func(t *testing.T) {
		dummyKey := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
		if _, err := gcm(dummyKey, nil, nil, nil, true); err == nil {
			t.Fatal("expected and error")
		}
	})
	for name, tv := range GCMTestVectors {
		t.Run("Encrypt/"+name, func(t *testing.T) {
			out, err := gcm(tv.Key, tv.Nonce, tv.Plaintext, tv.Aad, true)
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
			out, err := gcm(tv.Key, tv.Nonce, in, tv.Aad, false)
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
