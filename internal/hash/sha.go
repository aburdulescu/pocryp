package hash

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"bandr.me/p/pocryp/internal/common"
	"bandr.me/p/pocryp/internal/util/stdfile"
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

	sf, err := stdfile.New(*fInput, *fOutput)
	if err != nil {
		return err
	}
	defer sf.Close()

	hashFunc, err := common.HashFuncFrom(*fAlg)
	if err != nil {
		fset.Usage()
		return err
	}

	h := hashFunc()

	if _, err := io.Copy(h, sf.In); err != nil {
		return err
	}

	digest := h.Sum(nil)

	return sf.Write(digest, *fBin)
}
