package aes

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	poaes "bandr.me/p/pocryp/internal/aes"
)

func Cbc(args []string) error {
	fset := flag.NewFlagSet("aes-cbc", flag.ContinueOnError)
	fset.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: pocryp aes-cbc [-e/-d] -key/-key-file -iv [-in INPUT] [-out OUTPUT]

Encrypt/Decrypt INPUT to OUTPUT using AES-CBC.

If -in is not specified, stdin will be read.
If -out is not specified, the output will be printed to stdout.

Options:
`)
		fset.PrintDefaults()
	}

	fEncrypt := fset.Bool("e", false, "Encrypt the input to the output. Default if omitted.")
	fDecrypt := fset.Bool("d", false, "Decrypt the input to the output.")
	fOutput := fset.String("out", "", "Write the result to the file at path OUTPUT.")
	fInput := fset.String("in", "", "Read data from the file at path INPUT.")
	fKey := fset.String("key", "", "Key as hex.")
	fKeyFile := fset.String("key-file", "", "File which contains the key as binary/text.")
	fIV := fset.String("iv", "", "IV as hex.")

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

	if *fIV == "" {
		fset.Usage()
		return errors.New("no IV specified, use -iv to specify it")
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

	iv, err := hex.DecodeString(*fIV)
	if err != nil {
		return err
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

	var c cipher.BlockMode
	switch {
	case *fEncrypt:
		c, err = poaes.NewCBCEncrypter(key, iv)
	case *fDecrypt:
		c, err = poaes.NewCBCDecrypter(key, iv)
	default:
		c, err = poaes.NewCBCEncrypter(key, iv)
	}
	if err != nil {
		return err
	}

	output := poaes.CBCProcessBlocks(c, input.Bytes())

	if _, err := io.Copy(w, bytes.NewBuffer(output)); err != nil {
		return err
	}

	return nil
}
