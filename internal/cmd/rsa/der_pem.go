package rsa

import (
	"bytes"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

func DerPem(args []string) error {
	fset := flag.NewFlagSet("rsa-der-pem", flag.ContinueOnError)
	fset.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: pocryp rsa-der-pem -priv/-pub [-in INPUT] [-out OUTPUT]

Convert RSA key from PKCS#1 ASN.1 DER to PEM.

If -in is not specified, stdin will be read.
If -out is not specified, the output will be printed to stdout.

DER input must be specified in binary form.

Options:
`)
		fset.PrintDefaults()
	}

	fPriv := fset.Bool("priv", false, "Encode PrivateKey from given input.")
	fPub := fset.Bool("pub", false, "Encode PublicKey from given input.")
	fOutput := fset.String("out", "", "Write the result to the file at path OUTPUT.")
	fInput := fset.String("in", "", "Read data from the file at path INPUT.")

	if err := fset.Parse(args); err != nil {
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

	var input bytes.Buffer
	if _, err := io.Copy(&input, r); err != nil {
		return err
	}

	var blockType string
	switch {
	case *fPriv:
		blockType = "RSA PRIVATE KEY"
	case *fPub:
		blockType = "RSA PUBLIC KEY"
	default:
		fset.Usage()
		return errors.New("need to specify one of -priv or -pub")
	}

	block := &pem.Block{
		Type:  blockType,
		Bytes: input.Bytes(),
	}
	if err := pem.Encode(w, block); err != nil {
		return err
	}

	return nil
}
