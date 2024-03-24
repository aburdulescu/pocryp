package keygen

import (
	"crypto/rand"
	"errors"
	"strconv"

	"bandr.me/p/pocryp/internal/cli/cmd"
	"bandr.me/p/pocryp/internal/util/stdfile"
)

var AesCmd = &cmd.Command{
	Name:  "aes-keygen",
	Run:   runAes,
	Brief: "Generate AES key",

	Usage: `Usage: pocryp aes-keygen [-out OUTPUT] [-bin] NUM_BITS

Generate AES key.
Valid NUM_BITS: 128, 192, 256.

If -out is not specified, the output will be printed to stdout.
`,
}

func runAes(cmd *cmd.Command) error {
	fOutput := cmd.Flags.String("out", "", "Write the result to the file at path OUTPUT.")
	fBin := cmd.Flags.Bool("bin", false, "Write output as binary not hex.")

	if isHelp, err := cmd.Parse(); err != nil {
		if isHelp {
			return nil
		}
		return err
	}

	if cmd.Flags.NArg() == 0 {
		cmd.Flags.Usage()
		return errors.New("number of bits not specified")
	}

	numBits, err := strconv.Atoi(cmd.Flags.Arg(0))
	if err != nil {
		return err
	}

	if !(numBits == 128 || numBits == 192 || numBits == 256) {
		cmd.Flags.Usage()
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

	return sf.WriteHexOrBin(output, *fBin)
}
