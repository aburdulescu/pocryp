package rsa

import (
	"encoding/pem"
	"errors"

	"bandr.me/p/pocryp/internal/cli/cmd"
	"bandr.me/p/pocryp/internal/util/stdfile"
)

var Der2PemCmd = &cmd.Command{
	Name:  "rsa-der2pem",
	Run:   runDer2Pem,
	Brief: "Convert RSA key from PKCS#1 ASN.1 DER to PEM",

	Usage: `Usage: pocryp rsa-der2pem -priv/-pub [-in INPUT] [-out OUTPUT]

Convert RSA key from PKCS#1 ASN.1 DER to PEM.

If -in is not specified, stdin will be read.
If -out is not specified, the output will be printed to stdout.

DER input must be specified in binary form.
`,
}

func runDer2Pem(cmd *cmd.Command) error {
	fPriv := cmd.Flags.Bool("priv", false, "Encode PrivateKey from given input.")
	fPub := cmd.Flags.Bool("pub", false, "Encode PublicKey from given input.")
	fOutput := cmd.Flags.String("out", "", "Write the result to the file at path OUTPUT.")
	fInput := cmd.Flags.String("in", "", "Read data from the file at path INPUT.")

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

	var blockType string
	switch {
	case *fPriv:
		blockType = "RSA PRIVATE KEY"
	case *fPub:
		blockType = "RSA PUBLIC KEY"
	default:
		cmd.Flags.Usage()
		return errors.New("need to specify one of -priv or -pub")
	}

	block := &pem.Block{
		Type:  blockType,
		Bytes: input,
	}

	return pem.Encode(sf.Out, block)
}
