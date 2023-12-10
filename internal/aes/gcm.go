package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

func GcmCmd(args ...string) error {
	fset := flag.NewFlagSet("aes-gcm", flag.ContinueOnError)
	fset.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: pocryp aes-gcm [-e/-d] -key|-key-file -iv -aad [-in INPUT] [-out OUTPUT]

Encrypt/Decrypt INPUT to OUTPUT using AES-GCM.

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
	fAAD := fset.String("aad", "", "File which contains additional associated data as binary/text.")

	if err := fset.Parse(args); err != nil {
		return err
	}

	if *fKey == "" && *fKeyFile == "" {
		fset.Usage()
		return errors.New("no key specified, use -key or -key-file to specify it")
	}

	if *fKey != "" && *fKeyFile != "" {
		fset.Usage()
		return errors.New("cannot use -key and -key-file at the same time")
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

	var aad []byte
	if *fAAD != "" {
		b, err := os.ReadFile(*fAAD)
		if err != nil {
			return err
		}
		aad = b
	}

	in := os.Stdin
	if *fInput != "" {
		f, err := os.Open(*fInput)
		if err != nil {
			return err
		}
		defer f.Close()
		in = f
	}

	out := os.Stdout
	if *fOutput != "" {
		f, err := os.Create(*fOutput)
		if err != nil {
			return err
		}
		defer f.Close()
		out = f
	}

	var input bytes.Buffer
	if _, err := io.Copy(&input, in); err != nil {
		return err
	}

	var output []byte
	switch {
	case *fEncrypt:
		output, err = gcm(key, iv, input.Bytes(), aad, true)
	case *fDecrypt:
		output, err = gcm(key, iv, input.Bytes(), aad, false)
	default:
		output, err = gcm(key, iv, input.Bytes(), aad, true)
	}
	if err != nil {
		return err
	}

	if _, err := io.Copy(out, bytes.NewBuffer(output)); err != nil {
		return err
	}

	return nil
}

func gcm(key, nonce, in, additionalData []byte, direction bool) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	c, err := cipher.NewGCMWithNonceSize(block, len(nonce))
	if err != nil {
		return nil, err
	}
	if direction {
		return c.Seal(nil, nonce, in, additionalData), nil
	}
	return c.Open(nil, nonce, in, additionalData)
}
