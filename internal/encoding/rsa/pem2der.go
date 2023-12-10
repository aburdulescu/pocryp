package rsa

import (
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"

	"bandr.me/p/pocryp/internal/util/stdfile"
)

func Pem2DerCmd(args ...string) error {
	fset := flag.NewFlagSet("rsa-pem2der", flag.ContinueOnError)
	fset.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: pocryp rsa-pem2der [-bin] [-in INPUT] [-out OUTPUT]

Convert RSA key from PEM to PKCS#1 ASN.1 DER.

If -in is not specified, stdin will be read.
If -out is not specified, the output will be printed to stdout.

Options:
`)
		fset.PrintDefaults()
	}

	fOutput := fset.String("out", "", "Write the result to the file at path OUTPUT.")
	fInput := fset.String("in", "", "Read data from the file at path INPUT.")
	fBin := fset.Bool("bin", false, "Write output as binary not hex.")

	if err := fset.Parse(args); err != nil {
		return err
	}

	sf, err := stdfile.New(*fInput, *fOutput)
	if err != nil {
		return err
	}
	defer sf.Close()

	input, err := sf.Read()
	if err != nil {
		return err
	}

	block, _ := pem.Decode(input)
	if block == nil {
		return errors.New("failed to parse PEM block")
	}

	return sf.Write(block.Bytes, *fBin)
}
