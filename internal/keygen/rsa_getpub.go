package keygen

import (
	"crypto/x509"
	"encoding/pem"

	"bandr.me/p/pocryp/internal/cli/cmd"
	"bandr.me/p/pocryp/internal/encoding/rsa/util"
	"bandr.me/p/pocryp/internal/util/stdfile"
)

var RsaGetPubCmd = &cmd.Command{
	Name:  "rsa-getpub",
	Run:   runRsaGetPub,
	Brief: "Extract RSA public key from private key",

	Usage: `Usage: pocryp rsa-getpub [-in INPUT] [-out OUTPUT]

Extract RSA public key from private key, specified as PEM.

If -in is not specified, stdin will be read.
If -out is not specified, the output will be printed to stdout.
`,
}

func runRsaGetPub(cmd *cmd.Command) error {
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

	privKey, err := util.PrivateKeyFromPem(input)
	if err != nil {
		return err
	}

	pubKey := privKey.PublicKey

	pubKeyBlock := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&pubKey),
	}

	return pem.Encode(sf.Out, pubKeyBlock)
}
