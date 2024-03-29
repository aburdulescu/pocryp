package cmd

import (
	"fmt"

	"bandr.me/p/pocryp/internal/cli/cmd"
	"bandr.me/p/pocryp/internal/keywrap/aes"
	"bandr.me/p/pocryp/internal/util"
	"bandr.me/p/pocryp/internal/util/stdfile"
)

var Cmd = &cmd.Command{
	Name:  "aes-keywrap",
	Run:   run,
	Brief: "Wrap/Unwrap using AES-KEYWRAP",

	Usage: `Usage: pocryp aes-keywrap [-bin] [-w/-u] -key/-key-file [-in INPUT] [-out OUTPUT]

Wrap/Unwrap INPUT to OUTPUT using AES-KEYWRAP.

If -in is not specified, stdin will be read.
If -out is not specified, the output will be printed to stdout.
`,
}

func run(cmd *cmd.Command) error {
	fWrap := cmd.Flags.Bool("w", false, "Wrap the input to the output. Default if omitted.")
	fUnwrap := cmd.Flags.Bool("u", false, "Unwrap the input to the output.")
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
	case *fWrap:
		output, err = aes.Wrap(key, input)
	case *fUnwrap:
		output, err = aes.Unwrap(key, input)
	default:
		output, err = aes.Wrap(key, input)
	}
	if err != nil {
		return err
	}

	return sf.WriteHexOrBin(output, *fBin)
}
