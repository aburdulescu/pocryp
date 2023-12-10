package cmd

import (
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"

	"bandr.me/p/pocryp/internal/common"
	"bandr.me/p/pocryp/internal/util/stdfile"

	rsautil "bandr.me/p/pocryp/internal/encoding/rsa/util"
	kemrsa "bandr.me/p/pocryp/internal/kem/rsa"
)

func Run(args ...string) error {
	fset := flag.NewFlagSet("kem-rsa", flag.ContinueOnError)
	fset.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: pocryp kem-rsa [-e/-d] -key [-in INPUT] [-out OUTPUT]

Encapsulate/Decapsulate INPUT to OUTPUT using RSA-KEM.

If -in is not specified, stdin will be read.
If -out is not specified, the output will be printed to stdout.

Options:
`)
		fset.PrintDefaults()
	}

	fEncapsulate := fset.Bool("e", false, "Encapsulate the input to the output. Default if omitted.")
	fDecapsulate := fset.Bool("d", false, "Decapsulate the input to the output.")
	fOutput := fset.String("out", "", "Write the result to the file at path OUTPUT.")
	fInput := fset.String("in", "", "Read data from the file at path INPUT.")
	fKey := fset.String("key", "", "Path to file which contains the key in PEM format")
	fKdfSalt := fset.String("kdf-salt", "", "KDF salt as hex.")
	fKdfIter := fset.Int("kdf-iter", 5, "KDF iterations.")
	fKdfKeyLen := fset.Int("kdf-key-len", 16, "KDF key length.")
	fKdfHashFunc := fset.String(
		"kdf-hash-func",
		common.AlgSHA256,
		fmt.Sprintf("KDF hash function(valid options: %s).", common.SHAAlgs),
	)

	if err := fset.Parse(args); err != nil {
		return err
	}

	if *fKey == "" {
		fset.Usage()
		return errors.New("no key specified, use -key to specify it")
	}
	keyData, err := os.ReadFile(*fKey)
	if err != nil {
		return err
	}

	var key any
	switch {
	case *fDecapsulate:
		key, err = rsautil.PrivateKeyFromPem(keyData)
		if err != nil {
			return err
		}
	default:
		key, err = rsautil.PublicKeyFromPem(keyData)
		if err != nil {
			return err
		}
	}

	if *fKdfSalt == "" {
		fset.Usage()
		return errors.New("KDF salt cannot be empty")
	}
	kdfSalt, err := hex.DecodeString(*fKdfSalt)
	if err != nil {
		return err
	}

	kdfHashFunc, err := common.HashFuncFrom(*fKdfHashFunc)
	if err != nil {
		fset.Usage()
		return err
	}

	kdfParams := kemrsa.KDFParams{
		Salt:     kdfSalt,
		Iter:     *fKdfIter,
		KeyLen:   *fKdfKeyLen,
		HashFunc: kdfHashFunc,
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

	var output []byte
	switch {
	case *fEncapsulate:
		output, err = kemrsa.Encapsulate(key.(*rsa.PublicKey), input, kdfParams)
	case *fDecapsulate:
		output, err = kemrsa.Decapsulate(key.(*rsa.PrivateKey), input, kdfParams)
	default:
		output, err = kemrsa.Encapsulate(key.(*rsa.PublicKey), input, kdfParams)
	}
	if err != nil {
		return err
	}

	return sf.Write(output, true)
}
