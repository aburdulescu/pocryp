package rsa

import (
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"

	"bandr.me/p/pocryp/internal/cli/cmd"
)

var Der2RawCmd = &cmd.Command{
	Name:  "rsa-der2raw",
	Run:   runDer2Raw,
	Brief: "Convert RSA key from PKCS#1 ASN.1 DER to raw values(n, e, d, p, q)",

	Usage: `pocryp rsa-der2raw -priv/-pub DER

Convert RSA key from PKCS#1 ASN.1 DER to raw values(n, e, d, p, q).

DER must be specified in hex form.
`,
}

func runDer2Raw(cmd *cmd.Command) error {
	fPriv := cmd.Flags.Bool("priv", false, "Encode PrivateKey from given input.")
	fPub := cmd.Flags.Bool("pub", false, "Encode PublicKey from given input.")

	if err := cmd.Parse(); err != nil {
		return err
	}

	if cmd.Flags.NArg() != 1 {
		cmd.Flags.Usage()
		return errors.New("DER hex string not specified")
	}

	input, err := hex.DecodeString(cmd.Flags.Arg(0))
	if err != nil {
		return err
	}

	switch {
	case *fPriv:
		key, err := x509.ParsePKCS1PrivateKey(input)
		if err != nil {
			return err
		}
		fmt.Printf("n=%s\n", hex.EncodeToString(key.N.Bytes()))
		fmt.Printf("e=%x\n", key.E)
		fmt.Printf("d=%s\n", hex.EncodeToString(key.D.Bytes()))
		fmt.Printf("p=%s\n", hex.EncodeToString(key.Primes[0].Bytes()))
		fmt.Printf("q=%s\n", hex.EncodeToString(key.Primes[1].Bytes()))
	case *fPub:
		key, err := x509.ParsePKCS1PublicKey(input)
		if err != nil {
			return err
		}
		fmt.Printf("n=%s\n", hex.EncodeToString(key.N.Bytes()))
		fmt.Printf("e=%x\n", key.E)
	default:
		cmd.Flags.Usage()
		return errors.New("need to specify one of -priv or -pub")
	}

	return nil
}
