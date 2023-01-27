package aes

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestKeyGen(t *testing.T) {
	t.Run("NoArgs", func(t *testing.T) {
		if err := KeyGen(nil); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("InvalidNumBits", func(t *testing.T) {
		if err := KeyGen([]string{"4223"}); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("NumBitsNotInt", func(t *testing.T) {
		if err := KeyGen([]string{"hello"}); err == nil {
			t.Fatal("expected error")
		}
	})

	tmp := t.TempDir()

	tests := []string{"128", "192", "256"}

	for _, numBits := range tests {
		t.Run(numBits, func(t *testing.T) {
			outPath := filepath.Join(tmp, "out"+numBits)
			if err := KeyGen([]string{"-out", outPath, numBits}); err != nil {
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