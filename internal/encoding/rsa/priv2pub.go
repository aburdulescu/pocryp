package rsa

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"

	"bandr.me/p/pocryp/internal/encoding/rsa/util"
	"bandr.me/p/pocryp/internal/util/stdfile"
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

	sf, err := stdfile.New(*fInput, *fOutput)
	if err != nil {
		return err
	}
	defer sf.Close()

	input, err := sf.Read()
	if err != nil {
		return err
	}

	privKey, err := util.PrivateKeyFromPem(input)
	if err != nil {
		return err
	}

	pubKey := privKey.PublicKey

	pubKeyBlock := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&pubKey),
	}

	return pem.Encode(sf.Out, pubKeyBlock)
}
