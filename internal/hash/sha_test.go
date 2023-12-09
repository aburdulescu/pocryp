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
	// https: //csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha-3bytetestvectors.zip
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

		{
			name:   "Short",
			alg:    common.AlgSHA3_224,
			input:  string([]byte{0x2b, 0xbb, 0x42, 0xb9, 0x20, 0xb7, 0xfe, 0xb4, 0xe3, 0x96, 0x2a, 0x15, 0x52, 0xcc, 0x39, 0x0f}),
			output: "0dfa61f6b439bf8e3a6f378fe30a4134e8b2dfb652997a2a76c2789f",
		},

		{
			name:   "Short",
			alg:    common.AlgSHA3_256,
			input:  string([]byte{0xd8, 0x3c, 0x72, 0x1e, 0xe5, 0x1b, 0x06, 0x0c, 0x5a, 0x41, 0x43, 0x8a, 0x82, 0x21, 0xe0, 0x40}),
			output: "b87d9e4722edd3918729ded9a6d03af8256998ee088a1ae662ef4bcaff142a96",
		},

		{
			name:   "Short",
			alg:    common.AlgSHA3_384,
			input:  string([]byte{0x65, 0xb2, 0x7f, 0x6c, 0x55, 0x78, 0xa4, 0xd5, 0xd9, 0xf6, 0x51, 0x9c, 0x55, 0x4c, 0x30, 0x97}),
			output: "dd734f4987fe1a71455cf9fb1ee8986882c82448827a7880fc90d2043c33b5cbc0ed58b8529e4c6bc3a7288829e0a40d",
		},

		{
			name:   "Short",
			alg:    common.AlgSHA3_512,
			input:  string([]byte{0x05, 0x40, 0x95, 0xba, 0x53, 0x1e, 0xec, 0x22, 0x11, 0x3c, 0xc3, 0x45, 0xe8, 0x37, 0x95, 0xc7}),
			output: "f3adf5ccf2830cd621958021ef998252f2b6bc4c135096839586d5064a2978154ea076c600a97364bce0e9aab43b7f1f2da93537089de950557674ae6251ca4d",
		},
	}

	tmp := t.TempDir()

	for _, test := range tests {
		t.Run(test.alg+"-"+test.name, func(t *testing.T) {

			out := filepath.Join(tmp, "out")
			in := filepath.Join(tmp, "in")

			testutil.SetupInOut(t, in, out, []byte(test.input))

			args := []string{"-alg", test.alg, "-in", in, "-out", out, "-bin"}

			if err := ShaCmd(args...); err != nil {
				t.Fatal(err)
			}

			testutil.ExpectFileContentHex(t, out, test.output)
		})
	}
}
