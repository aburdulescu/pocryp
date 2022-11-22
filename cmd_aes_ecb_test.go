package main

import (
	"encoding/hex"
	"fmt"
	"path/filepath"
	"testing"

	poaes "bandr.me/p/pocryp/internal/aes"
)

func TestCmdAesEcb(t *testing.T) {
	tmp := t.TempDir()
	for name, tv := range poaes.ECBTestVectors {
		for i, in := range poaes.AesBlocks {
			t.Run(fmt.Sprintf("%s-Encrypt-%d", name, i), func(t *testing.T) {
				testCmdAesEcb(t, tmp, "-e", tv.Key, in, tv.Ciphertexts[i])
			})
		}
		for i, in := range tv.Ciphertexts {
			t.Run(fmt.Sprintf("%s-Decrypt-%d", name, i), func(t *testing.T) {
				testCmdAesEcb(t, tmp, "-d", tv.Key, in, poaes.AesBlocks[i])
			})
		}
		for i, in := range poaes.AesBlocks {
			t.Run(fmt.Sprintf("%s-Default-%d", name, i), func(t *testing.T) {
				testCmdAesEcb(t, tmp, "", tv.Key, in, tv.Ciphertexts[i])
			})
		}
	}
	t.Run("NoKey", func(t *testing.T) {
		if err := cmdAesEcb(nil); err == nil {
			t.Fatal("expected and error")
		}
	})
	t.Run("KeyAsHexAndFromFile", func(t *testing.T) {
		if err := cmdAesEcb([]string{"-key=0011", "-key-file=foo"}); err == nil {
			t.Fatal("expected and error")
		}
	})
}

func testCmdAesEcb(t *testing.T, tmp string, direction string, key, input, expected []byte) {
	out := filepath.Join(tmp, "out")
	in := filepath.Join(tmp, "in")
	setupInsAndOuts(t, in, out, input)
	var args []string
	if direction != "" {
		args = append(args, direction)
	}
	args = append(args,
		"-key", hex.EncodeToString(key),
		"-in", in,
		"-out", out,
	)
	if err := cmdAesEcb(args); err != nil {
		t.Fatal(err)
	}
	expectFileContent(t, out, expected)
}
