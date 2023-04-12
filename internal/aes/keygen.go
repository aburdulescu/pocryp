package aes

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
)

func KeyGen(args ...string) error {
	fset := flag.NewFlagSet("aes-keygen", flag.ContinueOnError)
	fset.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: pocryp aes-keygen [-out OUTPUT] [-bin] NUM_BITS

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

	var w io.Writer
	if *fOutput == "" {
		w = os.Stdout
	} else {
		f, err := os.Create(*fOutput)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}

	output := make([]byte, numBits)
	if _, err := rand.Read(output); err != nil {
		return err
	}

	if *fBin {
		if _, err := w.Write(output); err != nil {
			return err
		}
	} else {
		fmt.Fprintln(w, hex.EncodeToString(output))
	}

	return nil
}
