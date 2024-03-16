package aes

import (
	"crypto/aes"
	"encoding/hex"
	"fmt"

	"bandr.me/p/pocryp/internal/cli/cmd"
	"bandr.me/p/pocryp/internal/util"
	"bandr.me/p/pocryp/internal/util/stdfile"

	"github.com/aead/cmac"
)

var CmacGenerateCmd = &cmd.Command{
	Name:  "aes-cmac-generate",
	Run:   runCmacGenerate,
	Brief: "Generate MAC using AES-CMAC",

	Usage: `Usage: pocryp aes-cmac-generate [-bin] -key|-key-file [-in INPUT] [-out OUTPUT]

Generate MAC using AES-CMAC.

If -in is not specified, stdin will be read.
If -out is not specified, the output will be printed to stdout.
`,
}

func runCmacGenerate(cmd *cmd.Command) error {
	fOutput := cmd.Flags.String("out", "", "Write the result to the file at path OUTPUT.")
	fInput := cmd.Flags.String("in", "", "Read data from the file at path INPUT.")
	fKey := cmd.Flags.String("key", "", "Key as hex.")
	fKeyFile := cmd.Flags.String("key-file", "", "File which contains the key as binary/text.")
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

var CmacVerifyCmd = &cmd.Command{
	Name:  "aes-cmac-verify",
	Run:   runCmacVerify,
	Brief: "Verify MAC using AES-CMAC",

	Usage: `Usage: pocryp aes-cmac-verify -key|-key-file -in MESSAGE -mac MAC

Verify MAC using AES-CMAC.

If -in is not specified, stdin will be read.
`,
}

func runCmacVerify(cmd *cmd.Command) error {
	fInput := cmd.Flags.String("in", "", "Read message from the file at path INPUT.")
	fMac := cmd.Flags.String("mac", "", "Expected MAC as hex string.")
	fKey := cmd.Flags.String("key", "", "Key as hex.")
	fKeyFile := cmd.Flags.String("key-file", "", "File which contains the key as binary/text.")

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
