package cmd

import (
	"encoding/json"
	"os"

	"bandr.me/p/pocryp/internal/cli/cmd"
	"bandr.me/p/pocryp/internal/she/mup"
)

var ExampleCmd = &cmd.Command{
	Name:  "she-example",
	Run:   runExample,
	Brief: "Print example JSON input",

	Usage: `Usage: pocryp she-example

Print example JSON input to stdout.
`,
}

func runExample(cmd *cmd.Command) error {
	if isHelp, err := cmd.Parse(); err != nil {
		if isHelp {
			return nil
		}
		return err
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")

	input := mup.Input{
		UID:     "000000000000000000000000000000",
		ID:      0,
		AuthID:  0,
		AuthKey: "00000000000000000000000000000000",
		NewKey:  "00000000000000000000000000000000",
	}

	return enc.Encode(input)
}
