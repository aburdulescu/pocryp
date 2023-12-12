package aes

import (
	"path/filepath"
	"testing"

	"bandr.me/p/pocryp/internal/testutil"
)

func TestCmacCmd(t *testing.T) {
	const key = "2b7e151628aed2a6abf7158809cf4f3c"

	tests := []struct {
		msg string
		mac string
	}{
		{
			msg: "6bc1bee22e409f96e93d7e117393172a",
			mac: "070a16b46b4d4144f79bdd9dd04a287c",
		},
		{
			msg: "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411",
			mac: "dfa66747de9ae63030ca32611497c827",
		},
		{
			msg: "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
			mac: "51f0bebf7e3b9d92fc49741779363cfe",
		},
	}

	tmp := t.TempDir()

	t.Run("Generate", func(t *testing.T) {
		for _, test := range tests {
			msg := testutil.BytesFromHex(t, test.msg)

			in := filepath.Join(tmp, "in")
			out := filepath.Join(tmp, "out")
			testutil.SetupInOut(t, in, out, msg)

			args := []string{"-bin", "-key", key, "-in", in, "-out", out}

			if err := testutil.RunCmd(CmacGenerateCmd, args...); err != nil {
				t.Fatal(err)
			}

			testutil.ExpectFileContentHex(t, out, test.mac)
		}
	})

	t.Run("Verify", func(t *testing.T) {
		for _, test := range tests {
			msg := testutil.BytesFromHex(t, test.msg)

			in := filepath.Join(tmp, "in")
			testutil.SetupIn(t, in, msg)

			args := []string{"-key", key, "-in", in, "-mac", test.mac}

			if err := testutil.RunCmd(CmacVerifyCmd, args...); err != nil {
				t.Log("msg =", test.msg)
				t.Log("mac =", test.mac)
				t.Fatal(err)
			}
		}
	})

}
