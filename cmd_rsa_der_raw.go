package main

import (
	"crypto/x509"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
)

func cmdRsaDerRaw(args []string) error {
	fset := flag.NewFlagSet("rsa-der-raw", flag.ContinueOnError)
	fset.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: pocryp rsa-der-raw -priv/-pub DER

Convert RSA key from PKCS#1 ASN.1 DER to raw values(n, e, d, p, q).

Options:
`)
		fset.PrintDefaults()
		os.Exit(1)
	}

	fPriv := fset.Bool("priv", false, "Encode PrivateKey from given input.")
	fPub := fset.Bool("pub", false, "Encode PublicKey from given input.")

	if err := fset.Parse(args); err != nil {
		return err
	}

	if fset.NArg() != 1 {
		return errors.New("DER hex string not specified")
	}

	input, err := hex.DecodeString(fset.Arg(0))
	if err != nil {
		return err
	}

	switch {
	case *fPriv:
		key, err := x509.ParsePKCS1PrivateKey(input)
		if err != nil {
			return err
		}
		fmt.Printf("n=%s\n", hex.EncodeToString(key.N.Bytes()))
		fmt.Printf("e=%x\n", key.E)
		fmt.Printf("d=%s\n", hex.EncodeToString(key.D.Bytes()))
		fmt.Printf("p=%s\n", hex.EncodeToString(key.Primes[0].Bytes()))
		fmt.Printf("q=%s\n", hex.EncodeToString(key.Primes[1].Bytes()))
	case *fPub:
		key, err := x509.ParsePKCS1PublicKey(input)
		if err != nil {
			return err
		}
		fmt.Printf("n=%s\n", hex.EncodeToString(key.N.Bytes()))
		fmt.Printf("e=%x\n", key.E)
	default:
		return errors.New("need to specify one of -priv or -pub")
	}

	return nil
}
