package keygen

import (
	"os"
	"path/filepath"
	"testing"

	"bandr.me/p/pocryp/internal/testutil"

	rsautil "bandr.me/p/pocryp/internal/encoding/rsa/util"
)

func TestRsa(t *testing.T) {
	t.Run("UnknownArg", func(t *testing.T) {
		if err := testutil.RunCmd(RsaCmd, "-xxx"); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("NoArgs", func(t *testing.T) {
		if err := testutil.RunCmd(RsaCmd); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("InvalidNumBits", func(t *testing.T) {
		if err := testutil.RunCmd(RsaCmd, "23"); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("NumBitsNotInt", func(t *testing.T) {
		if err := testutil.RunCmd(RsaCmd, "hello"); err == nil {
			t.Fatal("expected error")
		}
	})

	tmp := t.TempDir()

	tests := []string{"2048", "3072", "4096"}

	for _, numBits := range tests {
		t.Run(numBits, func(t *testing.T) {
			outPath := filepath.Join(tmp, "out"+numBits)
			if err := testutil.RunCmd(RsaCmd, "-out", outPath, numBits); err != nil {
				t.Fatalf("%s: %v", numBits, err)
			}
			result, err := os.ReadFile(outPath)
			if err != nil {
				t.Fatal(err)
			}
			key, err := rsautil.PrivateKeyFromPem(result)
			if err != nil {
				t.Fatal(err)
			}
			if err := key.Validate(); err != nil {
				t.Fatal(err)
			}

		})
	}
}
