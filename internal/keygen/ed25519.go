package keygen

import (
	"crypto/ed25519"

	"bandr.me/p/pocryp/internal/cli/cmd"
	"bandr.me/p/pocryp/internal/util/stdfile"
)

var Ed25519Cmd = &cmd.Command{
	Name:  "ed25519-keygen",
	Run:   runEd25519,
	Brief: "Generate ED25519 key",

	Usage: `Usage: pocryp ed25519-keygen [-out OUTPUT] [-bin]

Generate ED25519 key.

If -out is not specified, the output will be printed to stdout.
`,
}

func runEd25519(cmd *cmd.Command) error {
	fOutput := cmd.Flags.String("out", "", "Write the result to the file at path OUTPUT.")
	fBin := cmd.Flags.Bool("bin", false, "Write output as binary not hex.")

	if isHelp, err := cmd.Parse(); err != nil {
		if isHelp {
			return nil
		}
		return err
	}

	sf, err := stdfile.New("", *fOutput)
	if err != nil {
		return err
	}
	defer sf.Close()

	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}

	return sf.Write(key, *fBin)
}
