package aes

import (
	"crypto/aes"
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"bandr.me/p/pocryp/internal/util"
	"bandr.me/p/pocryp/internal/util/stdfile"

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

	key, err := util.FileOrHex(*fKeyFile, *fKey)
	if err != nil {
		return fmt.Errorf("key: %w", err)
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

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	output, err := cmac.Sum(input, block, 16)
	if err != nil {
		return err
	}

	return sf.Write(output, *fBin)
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

	key, err := util.FileOrHex(*fKeyFile, *fKey)
	if err != nil {
		return fmt.Errorf("key: %w", err)
	}

	if *fMac == "" {
		return fmt.Errorf("-mac not specified")
	}
	mac, err := hex.DecodeString(*fMac)
	if err != nil {
		return err
	}

	sf, err := stdfile.New(*fInput, "")
	if err != nil {
		return err
	}
	defer sf.Close()

	input, err := sf.Read()
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	valid := cmac.Verify(mac, input, block, 16)
	if !valid {
		return fmt.Errorf("not valid")
	}

	return nil
}
