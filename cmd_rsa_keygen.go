package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
)

func cmdRsaKeyGen(args []string) error {
	fset := flag.NewFlagSet("rsa-keygen", flag.ContinueOnError)
	fset.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: pocryp rsa-keygen [-out OUTPUT] NUM_BITS

Generate RSA key.

If -out is not specified, the output will be printed to stdout.

Options:
`)
		fset.PrintDefaults()
		os.Exit(1)
	}

	fOutput := fset.String("out", "", "Write the result to the file at path OUTPUT.")

	if err := fset.Parse(args); err != nil {
		return err
	}

	if fset.NArg() == 0 {
		return errors.New("number of bits not specified")
	}

	numBits, err := strconv.Atoi(fset.Arg(0))
	if err != nil {
		return err
	}

	if !(numBits == 2048 || numBits == 3072 || numBits == 4096) {
		return errors.New("invalid num bits requested")
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

	key, err := rsa.GenerateKey(rand.Reader, numBits)
	if err != nil {
		return err
	}

	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	if err := pem.Encode(w, block); err != nil {
		return err
	}

	return nil
}
