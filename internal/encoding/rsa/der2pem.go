package rsa

import (
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"

	"bandr.me/p/pocryp/internal/util/stdfile"
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

	sf, err := stdfile.New(*fInput, *fOutput)
	if err != nil {
		return err
	}
	defer sf.Close()

	input, err := sf.Read()
	if err != nil {
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
		Bytes: input,
	}

	return pem.Encode(sf.Out, block)
}
