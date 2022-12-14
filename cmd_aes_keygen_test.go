package main

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestCmdAesKeyGen(t *testing.T) {
	t.Run("NoArgs", func(t *testing.T) {
		if err := cmdAesKeyGen(nil); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("InvalidNumBits", func(t *testing.T) {
		if err := cmdAesKeyGen([]string{"4223"}); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("NumBitsNotInt", func(t *testing.T) {
		if err := cmdAesKeyGen([]string{"hello"}); err == nil {
			t.Fatal("expected error")
		}
	})

	tmp := t.TempDir()

	tests := []string{"128", "192", "256"}

	for _, numBits := range tests {
		t.Run(numBits, func(t *testing.T) {
			outPath := filepath.Join(tmp, "out"+numBits)
			if err := cmdAesKeyGen([]string{"-out", outPath, numBits}); err != nil {
				t.Fatalf("%s: %v", numBits, err)
			}
			numBitsInt, _ := strconv.Atoi(numBits)
			numBytes := numBitsInt / 8
			result, err := os.ReadFile(outPath)
			if err != nil {
				t.Fatal(err)
			}
			if len(result) != numBytes {
				t.Fatalf("expected len=%d, have %d", numBytes, len(result))
			}
		})
	}
}
