package stdfile

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

type StdFile struct {
	in    *os.File
	stdin bool

	Out    *os.File
	stdout bool
}

func New(infile, outfile string) (*StdFile, error) {
	var r StdFile

	if infile == "" {
		r.in = os.Stdin
		r.stdin = true
	} else {
		f, err := os.Open(infile)
		if err != nil {
			return nil, err
		}
		r.in = f
		r.stdin = false
	}

	if outfile == "" {
		r.Out = os.Stdout
		r.stdout = true
	} else {
		f, err := os.Create(outfile)
		if err != nil {
			return nil, err
		}
		r.Out = f
		r.stdout = false
	}

	return &r, nil
}

func (f *StdFile) Close() error {
	if !f.stdin {
		if err := f.in.Close(); err != nil {
			return err
		}
	}
	if !f.stdout {
		if err := f.Out.Close(); err != nil {
			return err
		}
	}
	return nil
}

func (f *StdFile) Read() ([]byte, error) {
	var input bytes.Buffer
	if _, err := io.Copy(&input, f.in); err != nil {
		return nil, err
	}
	return input.Bytes(), nil
}

func (f *StdFile) Write(b []byte, bin bool) error {
	if bin {
		if _, err := f.Out.Write(b); err != nil {
			return err
		}
	} else {
		fmt.Fprintln(f.Out, hex.EncodeToString(b))
	}
	return nil
}
