package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	poaes "bandr.me/p/pocryp/internal/aes"
)

func TestCmdAesEcb(t *testing.T) {
	tmp := t.TempDir()
	for name, tv := range poaes.ECBTestVectors {
		for i, in := range poaes.ECBBlocks {
			t.Run(fmt.Sprintf("%s-Encrypt-%d", name, i), func(t *testing.T) {
				testCmdAesEcb(t, tmp, "-e", tv.Key, in, tv.Ciphertexts[i])
			})
		}
		for i, in := range tv.Ciphertexts {
			t.Run(fmt.Sprintf("%s-Decrypt-%d", name, i), func(t *testing.T) {
				testCmdAesEcb(t, tmp, "-d", tv.Key, in, poaes.ECBBlocks[i])
			})
		}
	}
}

func testCmdAesEcb(t *testing.T, tmp string, direction string, key, input, expected []byte) {
	out := filepath.Join(tmp, "out")
	in := filepath.Join(tmp, "in")

	if err := ioutil.WriteFile(in, input, 0666); err != nil {
		t.Fatal(err)
	}

	f, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	args := []string{
		direction,
		"-key", hex.EncodeToString(key),
		"-in", in,
		"-out", out,
	}

	if err := cmdAesEcb(args); err != nil {
		t.Fatal(err)
	}

	result, err := ioutil.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(expected, result) {
		t.Log("expected =", hex.EncodeToString(expected))
		t.Log("result   =", hex.EncodeToString(result))
		t.Fatal("not equal")
	}
}
