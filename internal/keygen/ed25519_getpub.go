package keygen

import (
	"crypto/ed25519"

	"bandr.me/p/pocryp/internal/cli/cmd"
	"bandr.me/p/pocryp/internal/util/stdfile"
)

var Ed25519GetPubCmd = &cmd.Command{
	Name:  "ed25519-getpub",
	Run:   runEd25519GetPub,
	Brief: "Extract ED25519 public key from private key",

	Usage: `Usage: pocryp ed25519-getpub [-in INPUT] [-out OUTPUT]

Extract ED25519 public key from private key.

If -in is not specified, stdin will be read.
If -out is not specified, the output will be printed to stdout.
`,
}

func runEd25519GetPub(cmd *cmd.Command) error {
	fOutput := cmd.Flags.String("out", "", "Write the result to the file at path OUTPUT.")
	fInput := cmd.Flags.String("in", "", "Read data from the file at path INPUT.")
	fBin := cmd.Flags.Bool("bin", false, "Write output as binary not hex.")

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

	priv := ed25519.PrivateKey(input)

	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		panic("could not convert to ed25519.PublicKey")
	}

	return sf.WriteHexOrBin(pub, *fBin)
}
