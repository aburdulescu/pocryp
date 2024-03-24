package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"bandr.me/p/pocryp/internal/cli/cmd"
	"bandr.me/p/pocryp/internal/util"
	"bandr.me/p/pocryp/internal/util/stdfile"
)

var GcmCmd = &cmd.Command{
	Name:  "aes-gcm",
	Run:   runGcm,
	Brief: "Encrypt/Decrypt using AES-GCM",

	Usage: `Usage: pocryp aes-gcm [-bin] [-e/-d] -key|-key-file -iv -aad [-in INPUT] [-out OUTPUT]

Encrypt/Decrypt INPUT to OUTPUT using AES-GCM.

If -in is not specified, stdin will be read.
If -out is not specified, the output will be printed to stdout.
`,
}

func runGcm(cmd *cmd.Command) error {
	fEncrypt := cmd.Flags.Bool("e", false, "Encrypt the input to the output. Default if omitted.")
	fDecrypt := cmd.Flags.Bool("d", false, "Decrypt the input to the output.")
	fOutput := cmd.Flags.String("out", "", "Write the result to the file at path OUTPUT.")
	fInput := cmd.Flags.String("in", "", "Read data from the file at path INPUT.")
	fKey := cmd.Flags.String("key", "", "Key as hex.")
	fKeyFile := cmd.Flags.String("key-file", "", "File which contains the key as binary/text.")
	fIV := cmd.Flags.String("iv", "", "IV as hex.")
	fAAD := cmd.Flags.String("aad", "", "File which contains additional associated data as binary/text.")
	fBin := cmd.Flags.Bool("bin", false, "Print output in binary form not hex.")

	if isHelp, err := cmd.Parse(); err != nil {
		if isHelp {
			return nil
		}
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

	var aad []byte
	if *fAAD != "" {
		b, err := os.ReadFile(*fAAD)
		if err != nil {
			return err
		}
		aad = b
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
		output, err = gcm(key, iv, input, aad, true)
	case *fDecrypt:
		output, err = gcm(key, iv, input, aad, false)
	default:
		output, err = gcm(key, iv, input, aad, true)
	}
	if err != nil {
		return err
	}

	return sf.WriteHexOrBin(output, *fBin)
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
