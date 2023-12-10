package keygen

import (
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
)

func Ed25519(args ...string) error {
	fset := flag.NewFlagSet("gen-ed25519", flag.ContinueOnError)
	fset.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: pocryp gen-ed25519 [-out OUTPUT] [-bin]

Generate ED25519 key.

If -out is not specified, the output will be printed to stdout.

Options:
`)
		fset.PrintDefaults()
	}

	fOutput := fset.String("out", "", "Write the result to the file at path OUTPUT.")
	fBin := fset.Bool("bin", false, "Write output as binary not hex.")

	if err := fset.Parse(args); err != nil {
		return err
	}

	var w io.Writer
	if *fOutput == "" {
		w = os.Stdout
	} else {
		f, err := os.Create(*fOutput)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}

	key, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}

	if *fBin {
		if _, err := w.Write(key); err != nil {
			return err
		}
	} else {
		fmt.Fprintln(w, hex.EncodeToString(key))
	}

	return nil
}
