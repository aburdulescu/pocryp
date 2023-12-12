package rsa

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"bandr.me/p/pocryp/internal/cli/cmd"
)

var Raw2DerCmd = &cmd.Command{
	Name:  "rsa-raw2der",
	Run:   runRaw2Der,
	Brief: "Convert RSA key from raw values(n, e, d, p, q) to PKCS#1 ASN.1 DER",

	Usage: `Usage: pocryp rsa-raw2der [-priv|-pub] -n modulus [-e publicExponent] -d privateExponent [-p prime1 -q prime2]

Convert RSA key from raw values(n, e, d, p, q) to PKCS#1 ASN.1 DER.
`,
}

func runRaw2Der(cmd *cmd.Command) error {
	fPriv := cmd.Flags.Bool("priv", false, "Encode PrivateKey from given inputs.")
	fPub := cmd.Flags.Bool("pub", false, "Encode PublicKey from given inputs.")
	fMod := cmd.Flags.String("n", "", "Modulus as hex string")
	fPubExp := cmd.Flags.Int("e", 0, "Public exponent as integer")
	fPrivExp := cmd.Flags.String("d", "", "Private exponent as hex string")
	fPrime1 := cmd.Flags.String("p", "", "First prime number as hex string")
	fPrime2 := cmd.Flags.String("q", "", "Second prime number as hex string")

	if err := cmd.Parse(); err != nil {
		return err
	}

	if *fMod == "" {
		cmd.Flags.Usage()
		return errors.New("modulus not specified, use -n to specify it")
	}

	if *fPub && *fPriv {
		cmd.Flags.Usage()
		return errors.New("cannot specify -priv and -pub at the same time, choose one")
	}

	nBytes, err := hex.DecodeString(*fMod)
	if err != nil {
		return err
	}
	n := new(big.Int)
	n.SetBytes(nBytes)

	var result []byte
	switch {
	case *fPriv:
		if *fPubExp == 0 {
			cmd.Flags.Usage()
			return errors.New("-e is needed")
		}
		if *fPrivExp == "" {
			cmd.Flags.Usage()
			return errors.New("-d is needed")
		}
		if *fPrime1 == "" {
			cmd.Flags.Usage()
			return errors.New("-p is needed")
		}
		if *fPrime2 == "" {
			cmd.Flags.Usage()
			return errors.New("-q is needed")
		}
		dBytes, err := hex.DecodeString(*fPrivExp)
		if err != nil {
			return err
		}
		d := new(big.Int)
		d.SetBytes(dBytes)
		pBytes, err := hex.DecodeString(*fPrime1)
		if err != nil {
			return err
		}
		p := new(big.Int)
		p.SetBytes(pBytes)
		qBytes, err := hex.DecodeString(*fPrime2)
		if err != nil {
			return err
		}
		q := new(big.Int)
		q.SetBytes(qBytes)
		key := &rsa.PrivateKey{
			PublicKey: rsa.PublicKey{
				N: n,
				E: *fPubExp,
			},
			D:      d,
			Primes: []*big.Int{p, q},
		}
		result = x509.MarshalPKCS1PrivateKey(key)
	case *fPub:
		if *fPubExp == 0 {
			cmd.Flags.Usage()
			return errors.New("-e is needed")
		}
		key := &rsa.PublicKey{
			N: n,
			E: *fPubExp,
		}
		result = x509.MarshalPKCS1PublicKey(key)
	default:
		cmd.Flags.Usage()
		return errors.New("need to specify one of -priv or -pub")
	}

	fmt.Println(hex.EncodeToString(result))

	return nil
}
