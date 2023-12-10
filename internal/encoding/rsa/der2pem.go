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

func Der2PemCmd(args ...string) error {
	fset := flag.NewFlagSet("rsa-der2pem", flag.ContinueOnError)
	fset.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: pocryp rsa-der2pem -priv/-pub [-in INPUT] [-out OUTPUT]

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
	if err := pem.Encode(out, block); err != nil {
		return err
	}

	return nil
}
