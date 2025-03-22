package cmd

import (
	"fmt"

	"bandr.me/p/pocryp/internal/cli/cmd"
	"bandr.me/p/pocryp/internal/padding/pkcs7"
	"bandr.me/p/pocryp/internal/util/stdfile"
)

var Cmd = &cmd.Command{
	Name:  "padding-pkcs7",
	Run:   run,
	Brief: "Pad/Unpad input using PKCS7",

	Usage: `Usage: pocryp padding-pkcs7 [-bin] [-p/-u] [-in INPUT] [-out OUTPUT]

Pad/Unpad INPUT to OUTPUT using PKCS7.

If -in is not specified, stdin will be read.
If -out is not specified, the output will be printed to stdout.
`,
}

func run(cmd *cmd.Command) error {
	fPad := cmd.Flags.Bool("p", false, "Padd the input to the output. Default if omitted.")
	fUnpad := cmd.Flags.Bool("u", false, "Unpad the input to the output.")
	fOutput := cmd.Flags.String("out", "", "Write the result to the file at path OUTPUT.")
	fInput := cmd.Flags.String("in", "", "Read data from the file at path INPUT.")
	fBin := cmd.Flags.Bool("bin", false, "Print output in binary form not hex.")
	fBlockSize := cmd.Flags.Uint("bs", 0, "Block size.")

	if isHelp, err := cmd.Parse(); err != nil {
		if isHelp {
			return nil
		}
		return err
	}

	if *fBlockSize == 0 || *fBlockSize > 255 {
		return fmt.Errorf("block size must be the following range [1, 255]")
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

	bs := byte(*fBlockSize)

	var output []byte
	switch {
	case *fPad:
		output = pkcs7.Pad(bs, input)
	case *fUnpad:
		output, err = pkcs7.Unpad(bs, input)
	default:
		output = pkcs7.Pad(bs, input)
	}
	if err != nil {
		return err
	}

	return sf.WriteHexOrBin(output, *fBin)
}
