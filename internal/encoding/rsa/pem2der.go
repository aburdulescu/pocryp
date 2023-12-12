package rsa

import (
	"encoding/pem"
	"errors"

	"bandr.me/p/pocryp/internal/cli/cmd"
	"bandr.me/p/pocryp/internal/util/stdfile"
)

var Pem2DerCmd = &cmd.Command{
	Name:  "rsa-pem2der",
	Run:   runPem2Der,
	Brief: "Convert RSA key from PEM to PKCS#1 ASN.1 DER",

	Usage: `Usage: pocryp rsa-pem2der [-bin] [-in INPUT] [-out OUTPUT]

Convert RSA key from PEM to PKCS#1 ASN.1 DER.

If -in is not specified, stdin will be read.
If -out is not specified, the output will be printed to stdout.
`,
}

func runPem2Der(cmd *cmd.Command) error {
	fOutput := cmd.Flags.String("out", "", "Write the result to the file at path OUTPUT.")
	fInput := cmd.Flags.String("in", "", "Read data from the file at path INPUT.")
	fBin := cmd.Flags.Bool("bin", false, "Write output as binary not hex.")

	if err := cmd.Parse(); err != nil {
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

	block, _ := pem.Decode(input)
	if block == nil {
		return errors.New("failed to parse PEM block")
	}

	return sf.Write(block.Bytes, *fBin)
}
