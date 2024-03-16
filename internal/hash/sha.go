package hash

import (
	"errors"
	"fmt"
	"io"

	"bandr.me/p/pocryp/internal/cli/cmd"
	"bandr.me/p/pocryp/internal/common"
	"bandr.me/p/pocryp/internal/util/stdfile"
)

var ShaCmd = &cmd.Command{
	Name:  "sha",
	Run:   runSha,
	Brief: "Generate cryptographic hash using SHA",

	Usage: `Usage: pocryp sha -alg [-bin] [-in INPUT] [-out OUTPUT]

Compute SHA digest of INPUT to OUTPUT.

If -in is not specified, stdin will be read.
If -out is not specified, the output will be printed to stdout.
`,
}

func runSha(cmd *cmd.Command) error {
	fOutput := cmd.Flags.String("out", "", "Write the result to the file at path OUTPUT.")
	fInput := cmd.Flags.String("in", "", "Read data from the file at path INPUT.")
	fAlg := cmd.Flags.String("alg", "", fmt.Sprintf("SHA algorithm to use; one of: %s.", common.SHAAlgs))
	fBin := cmd.Flags.Bool("bin", false, "Write output as binary not hex.")

	if err := cmd.Parse(); err != nil {
		return err
	}

	if *fAlg == "" {
		cmd.Flags.Usage()
		return errors.New("hash alg not specified, use -alg")
	}

	sf, err := stdfile.New(*fInput, *fOutput)
	if err != nil {
		return err
	}
	defer sf.Close()

	hashFunc, err := common.HashFuncFrom(*fAlg)
	if err != nil {
		cmd.Flags.Usage()
		return err
	}

	h := hashFunc()

	if _, err := io.Copy(h, sf.In); err != nil {
		return err
	}

	digest := h.Sum(nil)

	return sf.Write(digest, *fBin)
}
