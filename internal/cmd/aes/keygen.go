package aes

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
)

func KeyGen(args []string) error {
	fset := flag.NewFlagSet("aes-keygen", flag.ContinueOnError)
	fset.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: pocryp aes-keygen [-out OUTPUT] NUM_BITS

Generate AES key.

If -out is not specified, the output will be printed to stdout.

Options:
`)
		fset.PrintDefaults()
		os.Exit(1)
	}

	fOutput := fset.String("out", "", "Write the result to the file at path OUTPUT.")

	if err := fset.Parse(args); err != nil {
		return err
	}

	if fset.NArg() == 0 {
		return errors.New("number of bits not specified")
	}

	numBits, err := strconv.Atoi(fset.Arg(0))
	if err != nil {
		return err
	}

	if !(numBits == 128 || numBits == 192 || numBits == 256) {
		return errors.New("invalid num bits requested")
	}

	numBits /= 8

	output := make([]byte, numBits)
	if _, err := rand.Read(output); err != nil {
		return err
	}

	if *fOutput == "" {
		fmt.Println(hex.EncodeToString(output))
		return nil
	}

	f, err := os.Create(*fOutput)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := io.Copy(f, bytes.NewBuffer(output)); err != nil {
		return err
	}

	return nil
}
