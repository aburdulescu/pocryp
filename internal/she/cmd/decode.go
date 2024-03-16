package cmd

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"bandr.me/p/pocryp/internal/cli/cmd"
	"bandr.me/p/pocryp/internal/she/mup"
)

var DecodeCmd = &cmd.Command{
	Name:  "she-decode",
	Run:   runDecode,
	Brief: "Decode M1,M2,M3,M4,M5 to JSON input",

	Usage: `Usage: pocryp she-decode [hex_string]

Decode the M1,M2,M3,M4,M5 given as a hex string to its JSON form.
If no argument given, stdin will be read.
`,
}

func runDecode(cmd *cmd.Command) error {
	keyHex := cmd.Flags.String("key", "", "Secret key as hex")

	if err := cmd.Parse(); err != nil {
		return err
	}

	input := cmd.Flags.Arg(0)
	if cmd.Flags.NArg() == 0 {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("failed to read stdin: %w", err)
		}
		input = string(data)
	}
	input = strings.NewReplacer(" ", "", "\t", "", "\r", "", "\n", "").Replace(input)

	key, err := hex.DecodeString(*keyHex)
	if err != nil {
		return fmt.Errorf("failed to decode key: %w", err)
	}
	if len(key) != 16 {
		return fmt.Errorf("invalid key size: %d", len(key))
	}

	m1m2m3, err := hex.DecodeString(input)
	if err != nil {
		return fmt.Errorf("failed to decode input: %w", err)
	}

	result, err := mup.Decode(m1m2m3, key)
	if err != nil {
		return err
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")

	return enc.Encode(result)
}
