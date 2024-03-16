package cmd

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"bandr.me/p/pocryp/internal/cli/cmd"
	"bandr.me/p/pocryp/internal/she/mup"
)

var EncodeCmd = &cmd.Command{
	Name:  "she-encode",
	Run:   runEncode,
	Brief: "Encode JSON input to M1,M2,M3,M4,M5",

	Usage: `Usage: pocryp she-encode [input.json]

Encode the given JSON input file to M1,M2,M3,M4,M5.
If no argument given, stdin will be read.
`,
}

func runEncode(cmd *cmd.Command) error {
	oneLine := cmd.Flags.Bool("l", false, "Print everything on one line")

	if isHelp, err := cmd.Parse(); err != nil {
		if isHelp {
			return nil
		}
		return err
	}

	inFile := os.Stdin
	if cmd.Flags.NArg() > 0 {
		f, err := os.Open(cmd.Flags.Arg(0))
		if err != nil {
			return err
		}
		defer f.Close()
		inFile = f
	}

	var input mup.Input
	if err := json.NewDecoder(inFile).Decode(&input); err != nil {
		return err
	}

	result, err := input.Encode()
	if err != nil {
		return err
	}

	if *oneLine {
		fmt.Println(hex.EncodeToString(result[:]))
	} else {
		m1, m2, m3, m4, m5 := mup.SliceMs(result)
		fmt.Println(hex.EncodeToString(m1))
		fmt.Println(hex.EncodeToString(m2))
		fmt.Println(hex.EncodeToString(m3))
		fmt.Println(hex.EncodeToString(m4))
		fmt.Println(hex.EncodeToString(m5))
	}

	return nil
}
