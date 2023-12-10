package keygen

import (
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
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

	out := os.Stdout
	if *fOutput != "" {
		f, err := os.Create(*fOutput)
		if err != nil {
			return err
		}
		defer f.Close()
		out = f
	}

	key, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}

	if *fBin {
		if _, err := out.Write(key); err != nil {
			return err
		}
	} else {
		fmt.Fprintln(out, hex.EncodeToString(key))
	}

	return nil
}
