package cmd

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"

	"bandr.me/p/pocryp/internal/keywrap/aes"
	"bandr.me/p/pocryp/internal/util/stdfile"
)

func Run(args ...string) error {
	fset := flag.NewFlagSet("aes-keywrap", flag.ContinueOnError)
	fset.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: pocryp aes-keywrap [-w/-u] -key/-key-file [-in INPUT] [-out OUTPUT]

Wrap/Unwrap INPUT to OUTPUT using AES-KEYWRAP.

If -in is not specified, stdin will be read.
If -out is not specified, the output will be printed to stdout.

Options:
`)
		fset.PrintDefaults()
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
		fset.Usage()
		return errors.New("no key specified, use -k or --key-file to specify it")
	}
	if *fKey != "" && *fKeyFile != "" {
		fset.Usage()
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

	sf, err := stdfile.New(*fInput, *fOutput)
	if err != nil {
		return err
	}
	defer sf.Close()

	input, err := sf.Read()
	if err != nil {
		return err
	}

	var output []byte
	switch {
	case *fWrap:
		output, err = aes.Wrap(key, input)
	case *fUnwrap:
		output, err = aes.Unwrap(key, input)
	default:
		output, err = aes.Wrap(key, input)
	}
	if err != nil {
		return err
	}

	return sf.Write(output, true)
}
