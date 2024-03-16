package keygen

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strconv"

	"bandr.me/p/pocryp/internal/cli/cmd"
	"bandr.me/p/pocryp/internal/util/stdfile"
)

var RsaCmd = &cmd.Command{
	Name:  "rsa-keygen",
	Run:   runRsa,
	Brief: "Generate RSA key",

	Usage: `Usage: pocryp rsa-keygen [-out OUTPUT] NUM_BITS

Generate RSA key.
Valid NUM_BITS: 2048, 3072, 4096.

If -out is not specified, the output will be printed to stdout.
`,
}

func runRsa(cmd *cmd.Command) error {
	fOutput := cmd.Flags.String("out", "", "Write the result to the file at path OUTPUT.")

	if isHelp, err := cmd.Parse(); err != nil {
		if isHelp {
			return nil
		}
		return err
	}

	if cmd.Flags.NArg() == 0 {
		cmd.Flags.Usage()
		return errors.New("number of bits not specified")
	}

	numBits, err := strconv.Atoi(cmd.Flags.Arg(0))
	if err != nil {
		return err
	}

	if !(numBits == 2048 || numBits == 3072 || numBits == 4096) {
		cmd.Flags.Usage()
		return errors.New("invalid num bits requested")
	}

	sf, err := stdfile.New("", *fOutput)
	if err != nil {
		return err
	}
	defer sf.Close()

	key, err := rsa.GenerateKey(rand.Reader, numBits)
	if err != nil {
		return err
	}

	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	return pem.Encode(sf.Out, block)
}
