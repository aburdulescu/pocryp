package hash

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"bandr.me/p/pocryp/internal/common"
)

func ShaCmd(args ...string) error {
	fset := flag.NewFlagSet("hash-sha", flag.ContinueOnError)
	fset.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: pocryp hash-sha -alg [-bin] [-in INPUT] [-out OUTPUT]

Compute SHA digest of INPUT to OUTPUT.

If -in is not specified, stdin will be read.
If -out is not specified, the output will be printed to stdout.

Options:
`)
		fset.PrintDefaults()
	}

	fOutput := fset.String("out", "", "Write the result to the file at path OUTPUT.")
	fInput := fset.String("in", "", "Read data from the file at path INPUT.")
	fAlg := fset.String("alg", "", fmt.Sprintf("SHA algorithm to use; one of: %s.", common.SHAAlgs))
	fBin := fset.Bool("bin", false, "Write output as binary not hex.")

	if err := fset.Parse(args); err != nil {
		return err
	}

	if *fAlg == "" {
		fset.Usage()
		return errors.New("hash alg not specified, use -alg")
	}

	hashFunc, err := common.HashFuncFrom(*fAlg)
	if err != nil {
		fset.Usage()
		return err
	}

	var r io.Reader
	if *fInput == "" {
		r = os.Stdin
	} else {
		f, err := os.Open(*fInput)
		if err != nil {
			return err
		}
		defer f.Close()
		r = f
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

	h := hashFunc()

	if _, err := io.Copy(h, r); err != nil {
		return err
	}

	digest := h.Sum(nil)

	if *fBin {
		if _, err := w.Write(digest); err != nil {
			return err
		}
	} else {
		fmt.Fprintln(w, hex.EncodeToString(digest))
	}

	return nil
}
