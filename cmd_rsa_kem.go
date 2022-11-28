package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"os"

	porsa "bandr.me/p/pocryp/internal/rsa"
)

func cmdRsaKem(args []string) error {
	fset := flag.NewFlagSet("rsa-kem", flag.ContinueOnError)
	fset.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: pocryp rsa-kem [-e/-d] -key [-in INPUT] [-out OUTPUT]

Encapsulate/Decapsulate INPUT to OUTPUT using RSA-KEM.

If -in is not specified, stdin will be read.
If -out is not specified, the output will be printed to stdout.

Options:
`)
		fset.PrintDefaults()
		os.Exit(1)
	}

	fEncapsulate := fset.Bool("e", false, "Encapsulate the input to the output. Default if omitted.")
	fDecapsulate := fset.Bool("d", false, "Decapsulate the input to the output.")
	fOutput := fset.String("out", "", "Write the result to the file at path OUTPUT.")
	fInput := fset.String("in", "", "Read data from the file at path INPUT.")
	fKey := fset.String("key", "", "Path to file which contains the key in PEM format")
	fKdfSalt := fset.String("kdf-salt", "", "KDF salt as hex.")
	fKdfIter := fset.Int("kdf-iter", 5, "KDF iterations.")
	fKdfKeyLen := fset.Int("kdf-key-len", 16, "KDF key length.")
	fKdfHashFunc := fset.String("kdf-hash-func", "SHA-256", "KDF hash function(valid options: SHA-1, SHA-224, SHA-256, SHA-384 and SHA-512).")

	fset.Parse(args)

	if *fKey == "" {
		return errors.New("no key specified, use -key to specify it")
	}

	keyData, err := ioutil.ReadFile(*fKey)
	if err != nil {
		return err
	}
	var key any
	switch {
	case *fDecapsulate:
		key, err = porsa.PrivateKeyFromPem(keyData)
		if err != nil {
			return err
		}
	default:
		key, err = porsa.PublicKeyFromPem(keyData)
		if err != nil {
			return err
		}
	}

	if *fKdfSalt == "" {
		return errors.New("KDF salt cannot be empty")
	}
	kdfSalt, err := hex.DecodeString(*fKdfSalt)
	if err != nil {
		return err
	}
	var kdfHashFunc func() hash.Hash
	switch *fKdfHashFunc {
	case "SHA-1":
		kdfHashFunc = sha1.New
	case "SHA-224":
		kdfHashFunc = sha256.New224
	case "SHA-256":
		kdfHashFunc = sha256.New
	case "SHA-384":
		kdfHashFunc = sha512.New384
	case "SHA-512":
		kdfHashFunc = sha512.New
	default:
		return errors.New("KDF hash function is not valid")
	}
	kdfParams := porsa.KDFParams{
		Salt:     kdfSalt,
		Iter:     *fKdfIter,
		KeyLen:   *fKdfKeyLen,
		HashFunc: kdfHashFunc,
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

	var output []byte
	switch {
	case *fEncapsulate:
		output, err = porsa.KemEncapsulate(key.(*rsa.PublicKey), input.Bytes(), kdfParams)
	case *fDecapsulate:
		output, err = porsa.KemDecapsulate(key.(*rsa.PrivateKey), input.Bytes(), kdfParams)
	default:
		output, err = porsa.KemEncapsulate(key.(*rsa.PublicKey), input.Bytes(), kdfParams)
	}
	if err != nil {
		return err
	}

	if _, err := io.Copy(w, bytes.NewBuffer(output)); err != nil {
		return err
	}

	return nil
}
