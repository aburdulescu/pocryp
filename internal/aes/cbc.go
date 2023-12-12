package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"fmt"

	"bandr.me/p/pocryp/internal/cli/cmd"
	"bandr.me/p/pocryp/internal/util"
	"bandr.me/p/pocryp/internal/util/stdfile"
)

var CbcCmd = &cmd.Command{
	Name:  "aes-cbc",
	Run:   runCbc,
	Brief: "Encrypt/Decrypt using AES-CBC",

	Usage: `Usage: pocryp aes-cbc [-bin] [-e/-d] -key/-key-file -iv [-in INPUT] [-out OUTPUT]

Encrypt/Decrypt INPUT to OUTPUT using AES-CBC.

If -in is not specified, stdin will be read.
If -out is not specified, the output will be printed to stdout.
`,
}

func runCbc(cmd *cmd.Command) error {
	fEncrypt := cmd.Flags.Bool("e", false, "Encrypt the input to the output. Default if omitted.")
	fDecrypt := cmd.Flags.Bool("d", false, "Decrypt the input to the output.")
	fOutput := cmd.Flags.String("out", "", "Write the result to the file at path OUTPUT.")
	fInput := cmd.Flags.String("in", "", "Read data from the file at path INPUT.")
	fKey := cmd.Flags.String("key", "", "Key as hex.")
	fKeyFile := cmd.Flags.String("key-file", "", "File which contains the key as binary/text.")
	fIV := cmd.Flags.String("iv", "", "IV as hex.")
	fBin := cmd.Flags.Bool("bin", false, "Print output in binary form not hex.")

	if err := cmd.Parse(); err != nil {
		return err
	}

	key, err := util.FileOrHex(*fKeyFile, *fKey)
	if err != nil {
		return fmt.Errorf("key: %w", err)
	}

	if *fIV == "" {
		cmd.Flags.Usage()
		return errors.New("no IV specified, use -iv to specify it")
	}

	iv, err := hex.DecodeString(*fIV)
	if err != nil {
		return err
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

	var c cipher.BlockMode
	switch {
	case *fEncrypt:
		c, err = newCBCEncrypter(key, iv)
	case *fDecrypt:
		c, err = newCBCDecrypter(key, iv)
	default:
		c, err = newCBCEncrypter(key, iv)
	}
	if err != nil {
		return err
	}

	output := cbcProcessBlocks(c, input)

	return sf.Write(output, *fBin)
}

func newCBCEncrypter(key, iv []byte) (cipher.BlockMode, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCBCEncrypter(block, iv), nil
}

func newCBCDecrypter(key, iv []byte) (cipher.BlockMode, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCBCDecrypter(block, iv), nil
}

func cbcProcessBlocks(c cipher.BlockMode, in []byte) []byte {
	out := make([]byte, len(in))
	c.CryptBlocks(out, in)
	return out
}
