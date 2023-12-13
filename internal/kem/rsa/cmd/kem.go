package cmd

import (
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"bandr.me/p/pocryp/internal/cli/cmd"
	"bandr.me/p/pocryp/internal/common"
	"bandr.me/p/pocryp/internal/util/stdfile"

	rsautil "bandr.me/p/pocryp/internal/encoding/rsa/util"
	kemrsa "bandr.me/p/pocryp/internal/kem/rsa"
)

var Cmd = &cmd.Command{
	Name:  "rsa-kem",
	Run:   run,
	Brief: "Encapsulate/Decapsulate using RSA-KEM",

	Usage: `Usage: pocryp kem-rsa [-bin] [-e/-d] -key [-in INPUT] [-out OUTPUT]

Encapsulate/Decapsulate INPUT to OUTPUT using RSA-KEM.

If -in is not specified, stdin will be read.
If -out is not specified, the output will be printed to stdout.
`,
}

func run(cmd *cmd.Command) error {
	fEncapsulate := cmd.Flags.Bool("e", false, "Encapsulate the input to the output. Default if omitted.")
	fDecapsulate := cmd.Flags.Bool("d", false, "Decapsulate the input to the output.")
	fOutput := cmd.Flags.String("out", "", "Write the result to the file at path OUTPUT.")
	fInput := cmd.Flags.String("in", "", "Read data from the file at path INPUT.")
	fKey := cmd.Flags.String("key", "", "Path to file which contains the key in PEM format")
	fKdfSalt := cmd.Flags.String("kdf-salt", "", "KDF salt as hex.")
	fKdfIter := cmd.Flags.Int("kdf-iter", 5, "KDF iterations.")
	fKdfKeyLen := cmd.Flags.Int("kdf-key-len", 16, "KDF key length.")
	fKdfHashFunc := cmd.Flags.String(
		"kdf-hash-func",
		common.AlgSHA256,
		fmt.Sprintf("KDF hash function(valid options: %s).", common.SHAAlgs),
	)
	fBin := cmd.Flags.Bool("bin", false, "Print output in binary form not hex.")

	if err := cmd.Parse(); err != nil {
		return err
	}

	if *fKey == "" {
		cmd.Flags.Usage()
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
		cmd.Flags.Usage()
		return errors.New("KDF salt cannot be empty")
	}
	kdfSalt, err := hex.DecodeString(*fKdfSalt)
	if err != nil {
		return err
	}

	kdfHashFunc, err := common.HashFuncFrom(*fKdfHashFunc)
	if err != nil {
		cmd.Flags.Usage()
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

	return sf.Write(output, *fBin)
}
