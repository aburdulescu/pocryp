package rsa

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"

	"bandr.me/p/pocryp/internal/encoding/rsa/util"
)

func Priv2PubCmd(args ...string) error {
	fset := flag.NewFlagSet("rsa-priv2pub", flag.ContinueOnError)
	fset.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: pocryp rsa-priv2pub [-in INPUT] [-out OUTPUT]

Extract RSA public key from private key, specified as PEM.

If -in is not specified, stdin will be read.
If -out is not specified, the output will be printed to stdout.

Options:
`)
		fset.PrintDefaults()
	}

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

	privKey, err := util.PrivateKeyFromPem(input.Bytes())
	if err != nil {
		return err
	}

	pubKey := privKey.PublicKey

	pubKeyBlock := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&pubKey),
	}

	if err := pem.Encode(out, pubKeyBlock); err != nil {
		return err
	}

	return nil
}
