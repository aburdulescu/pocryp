package stdfile

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

type StdFile struct {
	In    *os.File
	stdin bool

	Out    *os.File
	stdout bool
}

func New(infile, outfile string) (*StdFile, error) {
	var r StdFile

	if infile == "" {
		r.In = os.Stdin
		r.stdin = true
	} else {
		f, err := os.Open(infile)
		if err != nil {
			return nil, err
		}
		r.In = f
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
		if err := f.In.Close(); err != nil {
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
	if _, err := io.Copy(&input, f.In); err != nil {
		return nil, err
	}
	return input.Bytes(), nil
}

func (f *StdFile) WriteHexOrBin(b []byte, bin bool) error {
	var err error
	if bin {
		_, err = f.Out.Write(b)
	} else {
		_, err = fmt.Fprintln(f.Out, hex.EncodeToString(b))
	}
	return err
}
