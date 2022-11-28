package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"os"
)

func cmdHashSha(args []string) error {
	fset := flag.NewFlagSet("hash-sha", flag.ContinueOnError)
	fset.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: pocryp hash-sha -alg [-bin] [-in INPUT] [-out OUTPUT]

Compute SHA digest of INPUT to OUTPUT.

If -in is not specified, stdin will be read.
If -out is not specified, the output will be printed to stdout.

Options:
`)
		fset.PrintDefaults()
		os.Exit(1)
	}

	fOutput := fset.String("out", "", "Write the result to the file at path OUTPUT.")
	fInput := fset.String("in", "", "Read data from the file at path INPUT.")
	fAlg := fset.String("alg", "", "SHA algorithm to use; one of: SHA-1, SHA-224, SHA-256, SHA-384, SHA-512.")
	fBin := fset.Bool("bin", false, "Write output as binary not hex.")

	fset.Parse(args)

	if *fAlg == "" {
		return errors.New("hash alg not specified, use -alg")
	}

	var hashfn hash.Hash
	switch *fAlg {
	case "SHA-1":
		hashfn = sha1.New()
	case "SHA-224":
		hashfn = sha256.New224()
	case "SHA-256":
		hashfn = sha256.New()
	case "SHA-384":
		hashfn = sha512.New384()
	case "SHA-512":
		hashfn = sha512.New()
	default:
		return errors.New("hash alg is not valid")
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

	if _, err := io.Copy(hashfn, r); err != nil {
		return err
	}

	digest := hashfn.Sum(nil)

	if *fBin {
		if _, err := w.Write(digest); err != nil {
			return err
		}
	} else {
		output := hex.EncodeToString(digest)
		fmt.Fprintln(w, output)
	}

	return nil
}
