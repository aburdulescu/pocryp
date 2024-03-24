package aes

import (
	"crypto/aes"
	"errors"
	"fmt"

	"bandr.me/p/pocryp/internal/cli/cmd"
	"bandr.me/p/pocryp/internal/util"
	"bandr.me/p/pocryp/internal/util/stdfile"
)

var EcbCmd = &cmd.Command{
	Name:  "aes-ecb",
	Run:   runEcb,
	Brief: "Encrypt/Decrypt using AES-ECB",

	Usage: `Usage: pocryp aes-ecb [-bin] [-e/-d] -key|-key-file [-in INPUT] [-out OUTPUT]

Encrypt/Decrypt INPUT to OUTPUT using AES-ECB.

If -in is not specified, stdin will be read.
If -out is not specified, the output will be printed to stdout.
`,
}

func runEcb(cmd *cmd.Command) error {
	fEncrypt := cmd.Flags.Bool("e", false, "Encrypt the input to the output. Default if omitted.")
	fDecrypt := cmd.Flags.Bool("d", false, "Decrypt the input to the output.")
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

	return sf.WriteHexOrBin(output, *fBin)
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
