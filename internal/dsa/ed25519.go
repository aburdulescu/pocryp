package dsa

import (
	"crypto"
	"crypto/ed25519"
	"fmt"

	"bandr.me/p/pocryp/internal/cli/cmd"
	"bandr.me/p/pocryp/internal/util"
	"bandr.me/p/pocryp/internal/util/stdfile"
)

var Ed25519SignCmd = &cmd.Command{
	Name:  "ed25519-sign",
	Run:   runEd25519Sign,
	Brief: "Generate signature using ED25519",

	Usage: `Usage: pocryp ed25519-sign [-bin] -key|-key-file [-in INPUT] [-out OUTPUT]

Generate signature using ED25519.

If -in is not specified, stdin will be read.
If -out is not specified, the output will be printed to stdout.
`,
}

func runEd25519Sign(cmd *cmd.Command) error {
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

	keyData, err := util.FileOrHex(*fKeyFile, *fKey)
	if err != nil {
		return fmt.Errorf("key: %w", err)
	}

	sf, err := stdfile.New(*fInput, *fOutput)
	if err != nil {
		return err
	}
	defer sf.Close()

	key := ed25519.PrivateKey(keyData)

	input, err := sf.Read()
	if err != nil {
		return err
	}

	output, err := key.Sign(nil, input, crypto.Hash(0))
	if err != nil {
		return err
	}

	return sf.WriteHexOrBin(output, *fBin)
}

var Ed25519VerifyCmd = &cmd.Command{
	Name:  "ed25519-verify",
	Run:   runEd25519Verify,
	Brief: "Verify signature using ED25519",

	Usage: `Usage: pocryp ed25519-verify -key|-key-file -sig|sig-file [-in INPUT]

Verify signature using ED25519.

If -in is not specified, stdin will be read.
`,
}

func runEd25519Verify(cmd *cmd.Command) error {
	fInput := cmd.Flags.String("in", "", "Read message from the file at path INPUT.")
	fSig := cmd.Flags.String("sig", "", "Expected signature as hex string.")
	fSigFile := cmd.Flags.String("sig-file", "", "File which contains the signature as binary/text.")
	fKey := cmd.Flags.String("key", "", "Key as hex.")
	fKeyFile := cmd.Flags.String("key-file", "", "File which contains the key as binary/text.")

	if isHelp, err := cmd.Parse(); err != nil {
		if isHelp {
			return nil
		}
		return err
	}

	keyData, err := util.FileOrHex(*fKeyFile, *fKey)
	if err != nil {
		return fmt.Errorf("key: %w", err)
	}

	sig, err := util.FileOrHex(*fSigFile, *fSig)
	if err != nil {
		return fmt.Errorf("sig: %w", err)
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

	key := ed25519.PublicKey(keyData)

	if ok := ed25519.Verify(key, input, sig); !ok {
		return fmt.Errorf("not valid")
	}

	return nil
}
