package keygen

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"

	"bandr.me/p/pocryp/internal/util/stdfile"
)

func Rsa(args ...string) error {
	fset := flag.NewFlagSet("rsa-keygen", flag.ContinueOnError)
	fset.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: pocryp gen-rsa [-out OUTPUT] NUM_BITS

Generate RSA key.
Valid NUM_BITS: 2048, 3072, 4096.

If -out is not specified, the output will be printed to stdout.

Options:
`)
		fset.PrintDefaults()
	}

	fOutput := fset.String("out", "", "Write the result to the file at path OUTPUT.")

	if err := fset.Parse(args); err != nil {
		return err
	}

	if fset.NArg() == 0 {
		fset.Usage()
		return errors.New("number of bits not specified")
	}

	numBits, err := strconv.Atoi(fset.Arg(0))
	if err != nil {
		return err
	}

	if !(numBits == 2048 || numBits == 3072 || numBits == 4096) {
		fset.Usage()
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
