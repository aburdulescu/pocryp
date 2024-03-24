package misc

import (
	"encoding/base64"
	"fmt"

	"bandr.me/p/pocryp/internal/cli/cmd"
	"bandr.me/p/pocryp/internal/util/stdfile"
)

var Base64Cmd = &cmd.Command{
	Name:  "base64",
	Run:   runBase64,
	Brief: "Base64 encode or decode",

	Usage: `Usage: pocryp base64 [-in INPUT] [-out OUTPUT]

Base64 encode or decode(if -d is specified) input to output.

If -in is not specified, stdin will be read.
If -out is not specified, the output will be printed to stdout.
`,
}

func runBase64(cmd *cmd.Command) error {
	fOutput := cmd.Flags.String("out", "", "Write the result to the file at path OUTPUT.")
	fInput := cmd.Flags.String("in", "", "Read data from the file at path INPUT.")
	fDecode := cmd.Flags.Bool("d", false, "Decode data.")

	if isHelp, err := cmd.Parse(); err != nil {
		if isHelp {
			return nil
		}
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

	var output string
	if *fDecode {
		b, err := base64.StdEncoding.DecodeString(string(input))
		if err != nil {
			return fmt.Errorf("failed to decode input: %w", err)
		}
		output = string(b)
	} else {
		output = base64.StdEncoding.EncodeToString(input)
	}

	fmt.Fprint(sf.Out, output)

	return nil
}
