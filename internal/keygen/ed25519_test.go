package keygen

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"

	"bandr.me/p/pocryp/internal/testutil"
)

func TestEd25519(t *testing.T) {
	t.Run("UnknownArg", func(t *testing.T) {
		if err := testutil.RunCmd(Ed25519Cmd, "-xxx"); err == nil {
			t.Fatal("expected error")
		}
	})

	tmp := t.TempDir()

	t.Run("Ok", func(t *testing.T) {
		outPath := filepath.Join(tmp, "out")
		if err := testutil.RunCmd(Ed25519Cmd, "-bin", "-out", outPath); err != nil {
			t.Fatal(err)
		}
		result, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatal(err)
		}
		if len(result) != ed25519.PrivateKeySize {
			t.Fatalf("len: want %d, have %d", ed25519.PrivateKeySize, len(result))
		}
	})

}
