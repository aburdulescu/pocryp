package hash

import (
	"path/filepath"
	"testing"

	"bandr.me/p/pocryp/internal/common"
	"bandr.me/p/pocryp/internal/testutil"
)

func TestShaCmd(t *testing.T) {

	t.Run("NoAlg", func(t *testing.T) {
		if err := ShaCmd(); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("InvalidAlg", func(t *testing.T) {
		if err := ShaCmd("-alg=foo"); err == nil {
			t.Fatal("expected error")
		}
	})

	type Test struct {
		name   string
		alg    string
		input  string
		output string
	}

	// sources:
	// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA1.pdf
	// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA224.pdf
	// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf
	// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA384.pdf
	// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512.pdf
	tests := []Test{

		{
			name:   "OneBlock",
			alg:    common.AlgSHA1,
			input:  "abc",
			output: "A9993E364706816ABA3E25717850C26C9CD0D89D",
		},
		{
			name:   "TwoBlocks",
			alg:    common.AlgSHA1,
			input:  "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
			output: "84983E441C3BD26EBAAE4AA1F95129E5E54670F1",
		},

		{
			name:   "OneBlock",
			alg:    common.AlgSHA224,
			input:  "abc",
			output: "23097D223405D8228642A477BDA255B32AADBCE4BDA0B3F7E36C9DA7",
		},
		{
			name:   "TwoBlocks",
			alg:    common.AlgSHA224,
			input:  "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
			output: "75388B16512776CC5DBA5DA1FD890150B0C6455CB4F58B1952522525",
		},

		{
			name:   "OneBlock",
			alg:    common.AlgSHA256,
			input:  "abc",
			output: "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD",
		},
		{
			name:   "TwoBlocks",
			alg:    common.AlgSHA256,
			input:  "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
			output: "248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1",
		},

		{
			name:   "OneBlock",
			alg:    common.AlgSHA384,
			input:  "abc",
			output: "CB00753F45A35E8BB5A03D699AC65007272C32AB0EDED1631A8B605A43FF5BED8086072BA1E7CC2358BAECA134C825A7",
		},
		{
			name:   "TwoBlocks",
			alg:    common.AlgSHA384,
			input:  "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
			output: "09330C33F71147E83D192FC782CD1B4753111B173B3B05D22FA08086E3B0F712FCC7C71A557E2DB966C3E9FA91746039",
		},

		{
			name:   "OneBlock",
			alg:    common.AlgSHA512,
			input:  "abc",
			output: "DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F",
		},
		{
			name:   "TwoBlocks",
			alg:    common.AlgSHA512,
			input:  "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
			output: "8E959B75DAE313DA8CF4F72814FC143F8F7779C6EB9F7FA17299AEADB6889018501D289E4900F7E4331B99DEC4B5433AC7D329EEB6DD26545E96E55B874BE909",
		},
	}

	tmp := t.TempDir()

	for _, test := range tests {
		t.Run(test.alg+"-"+test.name, func(t *testing.T) {

			out := filepath.Join(tmp, "out")
			in := filepath.Join(tmp, "in")

			testutil.SetupInsAndOuts(t, in, out, []byte(test.input))

			args := []string{
				"-alg", test.alg,
				"-in", in,
				"-out", out,
				"-bin",
			}

			if err := ShaCmd(args...); err != nil {
				t.Fatal(err)
			}

			testutil.ExpectFileContentHex(t, out, test.output)
		})
	}
}
