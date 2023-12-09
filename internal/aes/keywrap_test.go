package aes

import (
	"encoding/hex"
	"path/filepath"
	"testing"

	"bandr.me/p/pocryp/internal/aes/kw"
	"bandr.me/p/pocryp/internal/testutil"
)

func TestKeyWrapCmd(t *testing.T) {
	tmp := t.TempDir()
	for _, tv := range kw.TestVectors {
		t.Run("Wrap-"+tv.Name, func(t *testing.T) {
			testKeyWrapCmd(t, tmp, "-w", tv.Kek, tv.Plaintext, tv.Ciphertext)
		})
		t.Run("Unwrap-"+tv.Name, func(t *testing.T) {
			testKeyWrapCmd(t, tmp, "-u", tv.Kek, tv.Ciphertext, tv.Plaintext)
		})
		t.Run("Default-"+tv.Name, func(t *testing.T) {
			testKeyWrapCmd(t, tmp, "", tv.Kek, tv.Plaintext, tv.Ciphertext)
		})
	}
	t.Run("NoKey", func(t *testing.T) {
		if err := KeyWrapCmd(); err == nil {
			t.Fatal("expected and error")
		}
	})
	t.Run("KeyAsHexAndFromFile", func(t *testing.T) {
		if err := KeyWrapCmd("-key=0011", "-key-file=foo"); err == nil {
			t.Fatal("expected and error")
		}
	})
}

func testKeyWrapCmd(t *testing.T, tmp string, direction string, key, input, expected []byte) {
	out := filepath.Join(tmp, "out")
	in := filepath.Join(tmp, "in")
	testutil.SetupInOut(t, in, out, input)
	var args []string
	if direction != "" {
		args = append(args, direction)
	}
	args = append(args,
		"-key", hex.EncodeToString(key),
		"-in", in,
		"-out", out,
	)
	if err := KeyWrapCmd(args...); err != nil {
		t.Fatal(err)
	}
	testutil.ExpectFileContent(t, out, expected)
}
