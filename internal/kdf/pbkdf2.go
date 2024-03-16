package kdf

import (
	"fmt"

	"bandr.me/p/pocryp/internal/cli/cmd"
	"bandr.me/p/pocryp/internal/common"
	"bandr.me/p/pocryp/internal/util"
	"bandr.me/p/pocryp/internal/util/stdfile"

	"golang.org/x/crypto/pbkdf2"
)

var Pbkdf2Cmd = &cmd.Command{
	Name:  "pbkdf2",
	Run:   runPbkdf2,
	Brief: "Derive key using PBKDF2",

	Usage: `Usage: pocryp pbkdf2 [-bin] -key|-key-file -salt|-salt-file -iter -len -hash [-out OUTPUT]

Derive a new key from the given key using PBKDF2.

If -out is not specified, the output will be printed to stdout.
`,
}

func runPbkdf2(cmd *cmd.Command) error {
	fOutput := cmd.Flags.String("out", "", "Write the result to the file at path OUTPUT.")
	fKey := cmd.Flags.String("key", "", "Key as hex.")
	fKeyFile := cmd.Flags.String("key-file", "", "File which contains the key as binary/text.")
	fSalt := cmd.Flags.String("salt", "", "Salt as hex.")
	fSaltFile := cmd.Flags.String("salt-file", "", "File which contains the salt as binary/text.")
	fIter := cmd.Flags.Int("iter", 1024, "Number of iterations.")
	fLen := cmd.Flags.Int("len", 128, "Bit-length of the derived key.")
	fHashFunc := cmd.Flags.String(
		"hash",
		common.AlgSHA256,
		fmt.Sprintf("Hash function(valid options: %s).", common.SHAAlgs),
	)
	fBin := cmd.Flags.Bool("bin", false, "Print output in binary form not hex.")

	if err := cmd.Parse(); err != nil {
		return err
	}

	key, err := util.FileOrHex(*fKeyFile, *fKey)
	if err != nil {
		cmd.Flags.Usage()
		return fmt.Errorf("key: %w", err)
	}

	salt, err := util.FileOrHex(*fSaltFile, *fSalt)
	if err != nil {
		cmd.Flags.Usage()
		return fmt.Errorf("salt: %w", err)
	}

	hashFunc, err := common.HashFuncFrom(*fHashFunc)
	if err != nil {
		cmd.Flags.Usage()
		return err
	}

	sf, err := stdfile.New("", *fOutput)
	if err != nil {
		return err
	}
	defer sf.Close()

	output := pbkdf2.Key(key, salt, *fIter, *fLen, hashFunc)

	return sf.Write(output, *fBin)
}
