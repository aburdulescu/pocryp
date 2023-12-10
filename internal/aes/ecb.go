package aes

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

func EcbCmd(args ...string) error {
	fset := flag.NewFlagSet("aes-ecb", flag.ContinueOnError)
	fset.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: pocryp aes-ecb [-e/-d] -key|-key-file [-in INPUT] [-out OUTPUT]

Encrypt/Decrypt INPUT to OUTPUT using AES-ECB.

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

	var err error
	var output []byte
	switch {
	case *fEncrypt:
		output, err = ecb(key, input.Bytes(), true)
	case *fDecrypt:
		output, err = ecb(key, input.Bytes(), false)
	default:
		output, err = ecb(key, input.Bytes(), true)
	}
	if err != nil {
		return err
	}

	if _, err := io.Copy(out, bytes.NewBuffer(output)); err != nil {
		return err
	}

	return nil
}

func ecb(key, in []byte, direction bool) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	if len(in)%bs != 0 {
		return nil, errors.New("need a multiple of the blocksize")
	}
	result := make([]byte, len(in))
	out := result
	for len(in) > 0 {
		if direction {
			block.Encrypt(out, in)
		} else {
			block.Decrypt(out, in)
		}
		in = in[bs:]
		out = out[bs:]
	}
	return result, nil
}
