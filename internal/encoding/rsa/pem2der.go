package rsa

import (
	"bytes"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

func Pem2DerCmd(args ...string) error {
	fset := flag.NewFlagSet("rsa-pem2der", flag.ContinueOnError)
	fset.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: pocryp rsa-pem2der [-in INPUT] [-out OUTPUT]

Convert RSA key from PEM to PKCS#1 ASN.1 DER.

If -in is not specified, stdin will be read.
If -out is not specified, the output will be printed to stdout.

Options:
`)
		fset.PrintDefaults()
	}

	fOutput := fset.String("out", "", "Write the result to the file at path OUTPUT.")
	fInput := fset.String("in", "", "Read data from the file at path INPUT.")
	fPrintBin := fset.Bool("bin", false, "Print output in binary form.")

	if err := fset.Parse(args); err != nil {
		return err
	}

	in := os.Stdin
	if *fInput != "" {
		f, err := os.Open(*fInput)
		if err != nil {
			return err
		}
		defer f.Close()
		in = f
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

	var input bytes.Buffer
	if _, err := io.Copy(&input, in); err != nil {
		return err
	}

	block, _ := pem.Decode(input.Bytes())
	if block == nil {
		return errors.New("failed to parse PEM block")
	}

	if *fPrintBin {
		if _, err := io.Copy(out, bytes.NewBuffer(block.Bytes)); err != nil {
			return err
		}
	} else {
		fmt.Fprintln(out, hex.EncodeToString(block.Bytes))
	}

	return nil
}
