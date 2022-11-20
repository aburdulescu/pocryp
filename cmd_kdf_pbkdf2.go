package main

import (
	"bytes"
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

	"golang.org/x/crypto/pbkdf2"
)

func cmdKdfPbkdf2(args []string) error {
	fset := flag.NewFlagSet("kdf-pbkdf2", flag.ContinueOnError)
	fset.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: pocryp kdf-pbkdf2 -key|-key-file -salt|-salt-file -iter -len -hash [-out OUTPUT]

Derive a new key from the given key using PBKDF2.

If -in is not specified, stdin will be read.
If -out is not specified, the output will be printed to stdout.

Options:
`)
		fset.PrintDefaults()
		os.Exit(1)
	}

	fOutput := fset.String("out", "", "Write the result to the file at path OUTPUT.")
	fKey := fset.String("key", "", "Key as hex.")
	fKeyFile := fset.String("key-file", "", "File which contains the key as binary/text.")
	fSalt := fset.String("salt", "", "Salt as hex.")
	fSaltFile := fset.String("salt-file", "", "File which contains the salt as binary/text.")
	fIter := fset.Int("iter", 1024, "Number of iterations.")
	fLen := fset.Int("len", 128, "Bit-length of the derived key.")
	fHashFunc := fset.String("hash", "SHA-1", "Hash function(valid options: SHA-1, SHA-224, SHA-256, SHA-384 and SHA-512).")

	fset.Parse(args)

	if *fKey == "" && *fKeyFile == "" {
		return errors.New("no key specified, use -key or -key-file to specify it")
	}
	if *fKey != "" && *fKeyFile != "" {
		return errors.New("cannot use -key and -key-file at the same time")
	}

	if *fSalt == "" && *fSaltFile == "" {
		return errors.New("no salt specified, use -salt or -salt-file to specify it")
	}
	if *fSalt != "" && *fSaltFile != "" {
		return errors.New("cannot use -salt and -salt-file at the same time")
	}

	var hashFunc func() hash.Hash
	switch *fHashFunc {
	case "SHA-1":
		hashFunc = sha1.New
	case "SHA-224":
		hashFunc = sha256.New224
	case "SHA-256":
		hashFunc = sha256.New
	case "SHA-384":
		hashFunc = sha512.New384
	case "SHA-512":
		hashFunc = sha512.New
	default:
		return errors.New("hash function is not valid")
	}

	var key []byte
	if *fKey != "" {
		b, err := hex.DecodeString(*fKey)
		if err != nil {
			return err
		}
		key = b
	}
	if *fKeyFile != "" {
		b, err := ioutil.ReadFile(*fKeyFile)
		if err != nil {
			return err
		}
		key = b
	}

	var salt []byte
	if *fSalt != "" {
		b, err := hex.DecodeString(*fSalt)
		if err != nil {
			return err
		}
		salt = b
	}
	if *fSaltFile != "" {
		b, err := ioutil.ReadFile(*fSaltFile)
		if err != nil {
			return err
		}
		salt = b
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

	output := pbkdf2.Key(key, salt, *fIter, *fLen, hashFunc)

	if _, err := io.Copy(w, bytes.NewBuffer(output)); err != nil {
		return err
	}

	return nil
}
