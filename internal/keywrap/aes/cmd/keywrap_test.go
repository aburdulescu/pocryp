package cmd

import (
	"encoding/hex"
	"path/filepath"
	"testing"

	"bandr.me/p/pocryp/internal/keywrap/aes"
	"bandr.me/p/pocryp/internal/testutil"
)

func TestCmd(t *testing.T) {
	tmp := t.TempDir()
	for _, tv := range aes.TestVectors {
		t.Run("Wrap-"+tv.Name, func(t *testing.T) {
			testCmd(t, tmp, "-w", tv.Kek, tv.Plaintext, tv.Ciphertext)
		})
		t.Run("Unwrap-"+tv.Name, func(t *testing.T) {
			testCmd(t, tmp, "-u", tv.Kek, tv.Ciphertext, tv.Plaintext)
		})
		t.Run("Default-"+tv.Name, func(t *testing.T) {
			testCmd(t, tmp, "", tv.Kek, tv.Plaintext, tv.Ciphertext)
		})
	}
	t.Run("NoKey", func(t *testing.T) {
		if err := Run(); err == nil {
			t.Fatal("expected and error")
		}
	})
	t.Run("KeyAsHexAndFromFile", func(t *testing.T) {
		if err := Run("-key=0011", "-key-file=foo"); err == nil {
			t.Fatal("expected and error")
		}
	})
}

func testCmd(t *testing.T, tmp string, direction string, key, input, expected []byte) {
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
		"-in", in,
		"-out", out,
	)
	if err := Run(args...); err != nil {
		t.Fatal(err)
	}
	testutil.ExpectFileContent(t, out, expected)
}
