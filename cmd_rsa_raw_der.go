package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
)

func cmdRsaRawDer(args []string) error {
	fset := flag.NewFlagSet("rsa-raw-der", flag.ContinueOnError)
	fset.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: pocryp rsa-raw-der [-priv|-pub] -n modulus [-e publicExponent] -d privateExponent [-p prime1 -q prime2]

Convert RSA key from raw values(n, e, d, p, q) to PKCS#1 ASN.1 DER.

Options:
`)
		fset.PrintDefaults()
		os.Exit(1)
	}

	fPriv := fset.Bool("priv", false, "Encode PrivateKey from given inputs.")
	fPub := fset.Bool("pub", false, "Encode PublicKey from given inputs.")
	fMod := fset.String("n", "", "Modulus as hex string")
	fPubExp := fset.Int("e", 0, "Public exponent as integer")
	fPrivExp := fset.String("d", "", "Private exponent as hex string")
	fPrime1 := fset.String("p", "", "First prime number as hex string")
	fPrime2 := fset.String("q", "", "Second prime number as hex string")

	fset.Parse(args)

	if *fMod == "" {
		return errors.New("modulus not specified, use -n to specify it")
	}

	if *fPub && *fPriv {
		return errors.New("cannot specify -priv and -pub at the same time, choose one")
	}

	nBytes, err := hex.DecodeString(*fMod)
	if err != nil {
		return err
	}
	n := new(big.Int)
	n.SetBytes(nBytes)

	var result []byte
	switch {
	case *fPriv:
		if *fPubExp == 0 {
			return errors.New("-e is needed")
		}
		if *fPrivExp == "" {
			return errors.New("-d is needed")
		}
		if *fPrime1 == "" {
			return errors.New("-p is needed")
		}
		if *fPrime2 == "" {
			return errors.New("-q is needed")
		}
		dBytes, err := hex.DecodeString(*fPrivExp)
		if err != nil {
			return err
		}
		d := new(big.Int)
		d.SetBytes(dBytes)
		pBytes, err := hex.DecodeString(*fPrime1)
		if err != nil {
			return err
		}
		p := new(big.Int)
		p.SetBytes(pBytes)
		qBytes, err := hex.DecodeString(*fPrime2)
		if err != nil {
			return err
		}
		q := new(big.Int)
		q.SetBytes(qBytes)
		key := &rsa.PrivateKey{
			PublicKey: rsa.PublicKey{
				N: n,
				E: *fPubExp,
			},
			D:      d,
			Primes: []*big.Int{p, q},
		}
		result = x509.MarshalPKCS1PrivateKey(key)
	case *fPub:
		if *fPubExp == 0 {
			return errors.New("-e is needed")
		}
		key := &rsa.PublicKey{
			N: n,
			E: *fPubExp,
		}
		result = x509.MarshalPKCS1PublicKey(key)
	default:
		return errors.New("need to specify one of -priv or -pub")
	}

	fmt.Println(hex.EncodeToString(result))

	return nil
}
