package keygen

import (
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"

	"bandr.me/p/pocryp/internal/util/stdfile"
)

func Aes(args ...string) error {
	fset := flag.NewFlagSet("gen-aes", flag.ContinueOnError)
	fset.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: pocryp gen-aes [-out OUTPUT] [-bin] NUM_BITS

Generate AES key.
Valid NUM_BITS: 128, 192, 256.

If -out is not specified, the output will be printed to stdout.

Options:
`)
		fset.PrintDefaults()
	}

	fOutput := fset.String("out", "", "Write the result to the file at path OUTPUT.")
	fBin := fset.Bool("bin", false, "Write output as binary not hex.")

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

	if !(numBits == 128 || numBits == 192 || numBits == 256) {
		fset.Usage()
		return errors.New("invalid num bits requested")
	}
	numBits /= 8

	sf, err := stdfile.New("", *fOutput)
	if err != nil {
		return err
	}
	defer sf.Close()

	output := make([]byte, numBits)
	if _, err := rand.Read(output); err != nil {
		return err
	}

	return sf.Write(output, *fBin)
}
