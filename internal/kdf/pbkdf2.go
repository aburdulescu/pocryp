package kdf

import (
	"flag"
	"fmt"
	"os"

	"bandr.me/p/pocryp/internal/common"
	"bandr.me/p/pocryp/internal/util"
	"bandr.me/p/pocryp/internal/util/stdfile"

	"golang.org/x/crypto/pbkdf2"
)

func Pbkdf2Cmd(args ...string) error {
	fset := flag.NewFlagSet("kdf-pbkdf2", flag.ContinueOnError)
	fset.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: pocryp kdf-pbkdf2 -key|-key-file -salt|-salt-file -iter -len -hash [-out OUTPUT]

Derive a new key from the given key using PBKDF2.

If -out is not specified, the output will be printed to stdout.

Options:
`)
		fset.PrintDefaults()
	}

	fOutput := fset.String("out", "", "Write the result to the file at path OUTPUT.")
	fKey := fset.String("key", "", "Key as hex.")
	fKeyFile := fset.String("key-file", "", "File which contains the key as binary/text.")
	fSalt := fset.String("salt", "", "Salt as hex.")
	fSaltFile := fset.String("salt-file", "", "File which contains the salt as binary/text.")
	fIter := fset.Int("iter", 1024, "Number of iterations.")
	fLen := fset.Int("len", 128, "Bit-length of the derived key.")
	fHashFunc := fset.String(
		"hash",
		common.AlgSHA256,
		fmt.Sprintf("Hash function(valid options: %s).", common.SHAAlgs),
	)

	if err := fset.Parse(args); err != nil {
		return err
	}

	key, err := util.FileOrHex(*fKeyFile, *fKey)
	if err != nil {
		fset.Usage()
		return fmt.Errorf("key: %w", err)
	}

	salt, err := util.FileOrHex(*fSaltFile, *fSalt)
	if err != nil {
		fset.Usage()
		return fmt.Errorf("salt: %w", err)
	}

	hashFunc, err := common.HashFuncFrom(*fHashFunc)
	if err != nil {
		fset.Usage()
		return err
	}

	sf, err := stdfile.New("", *fOutput)
	if err != nil {
		return err
	}
	defer sf.Close()

	output := pbkdf2.Key(key, salt, *fIter, *fLen, hashFunc)

	return sf.Write(output, true)
}
