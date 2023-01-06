package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	poaes "bandr.me/p/pocryp/internal/aes"
)

func cmdAesKeywrap(args []string) error {
	fset := flag.NewFlagSet("aes-keywrap", flag.ContinueOnError)
	fset.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: pocryp aes-keywrap [-w/-u] -key/-key-file [-in INPUT] [-out OUTPUT]

Wrap/Unwrap INPUT to OUTPUT using AES-KEYWRAP.

If -in is not specified, stdin will be read.
If -out is not specified, the output will be printed to stdout.

Options:
`)
		fset.PrintDefaults()
		os.Exit(1)
	}

	fWrap := fset.Bool("w", false, "Wrap the input to the output. Default if omitted.")
	fUnwrap := fset.Bool("u", false, "Unwrap the input to the output.")
	fOutput := fset.String("out", "", "Write the result to the file at path OUTPUT.")
	fInput := fset.String("in", "", "Read data from the file at path INPUT.")
	fKey := fset.String("key", "", "Key as hex.")
	fKeyFile := fset.String("key-file", "", "File which contains the key as binary/text.")

	if err := fset.Parse(args); err != nil {
		return err
	}

	if *fKey == "" && *fKeyFile == "" {
		return errors.New("no key specified, use -k or --key-file to specify it")
	}
	if *fKey != "" && *fKeyFile != "" {
		return errors.New("cannot use -k and --key-file at the same time")
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
		b, err := os.ReadFile(*fKeyFile)
		if err != nil {
			return err
		}
		key = b
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
	var err error
	switch {
	case *fWrap:
		output, err = poaes.KeyWrap(key, input.Bytes())
	case *fUnwrap:
		output, err = poaes.KeyUnwrap(key, input.Bytes())
	default:
		output, err = poaes.KeyWrap(key, input.Bytes())
	}
	if err != nil {
		return err
	}

	if _, err := io.Copy(w, bytes.NewBuffer(output)); err != nil {
		return err
	}

	return nil
}
