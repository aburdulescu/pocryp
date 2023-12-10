package keygen

import (
	"crypto/ed25519"
	"flag"
	"fmt"
	"os"

	"bandr.me/p/pocryp/internal/util/stdfile"
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

	sf, err := stdfile.New("", *fOutput)
	if err != nil {
		return err
	}
	defer sf.Close()

	key, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}

	return sf.Write(key, *fBin)
}
