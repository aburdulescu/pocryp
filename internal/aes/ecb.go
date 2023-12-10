package aes

import (
	"crypto/aes"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"

	"bandr.me/p/pocryp/internal/util/stdfile"
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
	case *fEncrypt:
		output, err = ecb(key, input, true)
	case *fDecrypt:
		output, err = ecb(key, input, false)
	default:
		output, err = ecb(key, input, true)
	}
	if err != nil {
		return err
	}

	return sf.Write(output, true)
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
