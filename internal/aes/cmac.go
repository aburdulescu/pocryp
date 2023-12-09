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

	"github.com/aead/cmac"
)

func CmacGenerateCmd(args ...string) error {
	fset := flag.NewFlagSet("aes-cmac-generate", flag.ContinueOnError)
	fset.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: pocryp aes-cmac-generate [-bin] -key|-key-file [-in INPUT] [-out OUTPUT]

Generate MAC using AES-CMAC.

If -in is not specified, stdin will be read.
If -out is not specified, the output will be printed to stdout.

Options:
`)
		fset.PrintDefaults()
	}

	fOutput := fset.String("out", "", "Write the result to the file at path OUTPUT.")
	fInput := fset.String("in", "", "Read data from the file at path INPUT.")
	fKey := fset.String("key", "", "Key as hex.")
	fKeyFile := fset.String("key-file", "", "File which contains the key as binary/text.")
	fBin := fset.Bool("bin", false, "Print output in binary form not hex.")

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

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	output, err := cmac.Sum(input.Bytes(), block, 16)
	if err != nil {
		return err
	}

	if *fBin {
		if _, err := io.Copy(w, bytes.NewBuffer(output)); err != nil {
			return err
		}
	} else {
		fmt.Fprintln(w, hex.EncodeToString(output))
	}

	return nil
}

func CmacVerifyCmd(args ...string) error {
	fset := flag.NewFlagSet("aes-cmac-verify", flag.ContinueOnError)
	fset.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: pocryp aes-cmac-verify -key|-key-file -in MESSAGE -mac MAC

Verify MAC using AES-CMAC.

If -in is not specified, stdin will be read.

Options:
`)
		fset.PrintDefaults()
	}

	fInput := fset.String("in", "", "Read message from the file at path INPUT.")
	fMac := fset.String("mac", "", "Expected MAC as hex string.")
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

	if *fMac == "" {
		return fmt.Errorf("-mac not specified")
	}
	mac, err := hex.DecodeString(*fMac)
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

	var input bytes.Buffer
	if _, err := io.Copy(&input, r); err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	valid := cmac.Verify(mac, input.Bytes(), block, 16)
	if !valid {
		return fmt.Errorf("not valid")
	}

	return nil
}
