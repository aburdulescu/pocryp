package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func bytesFromHex(t testing.TB, s string) []byte {
	r, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestCmdKdfPbkdf2(t *testing.T) {
	type testvector struct {
		p        []byte
		s        []byte
		c        int
		dkLen    int
		expected []byte
	}
	// based on RFC6070
	tvs := []testvector{
		{
			p:        []byte("password"),
			s:        []byte("salt"),
			c:        2,
			dkLen:    20,
			expected: bytesFromHex(t, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"),
		},
		{
			p:        []byte("passwordPASSWORDpassword"),
			s:        []byte("saltSALTsaltSALTsaltSALTsaltSALTsalt"),
			c:        4096,
			dkLen:    25,
			expected: bytesFromHex(t, "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"),
		},
		{
			p:        []byte{'p', 'a', 's', 's', 0, 'w', 'o', 'r', 'd'},
			s:        []byte{'s', 'a', 0, 'l', 't'},
			c:        4096,
			dkLen:    16,
			expected: bytesFromHex(t, "56fa6aa75548099dcc37d7f03425e0c3"),
		},
	}
	tmp := t.TempDir()
	out := filepath.Join(tmp, "out")
	for i, tv := range tvs {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			f, err := os.Create(out)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			args := []string{
				"-key", hex.EncodeToString(tv.p),
				"-salt", hex.EncodeToString(tv.s),
				"-iter", fmt.Sprintf("%d", tv.c),
				"-len", fmt.Sprintf("%d", tv.dkLen),
				"-hash=SHA-1",
				"-out", out,
			}
			if err := cmdKdfPbkdf2(args); err != nil {
				t.Fatal(err)
			}
			result, err := os.ReadFile(out)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(tv.expected, result) {
				t.Log("expected =", hex.EncodeToString(tv.expected))
				t.Log("result   =", hex.EncodeToString(result))
				t.Fatal("not equal")
			}
		})
	}
	t.Run("NoKey", func(t *testing.T) {
		if err := cmdKdfPbkdf2(nil); err == nil {
			t.Fatal("expected and error")
		}
	})
	t.Run("KeyAsHexAndFromFile", func(t *testing.T) {
		if err := cmdKdfPbkdf2([]string{"-key=0011", "-key-file=foo"}); err == nil {
			t.Fatal("expected and error")
		}
	})
	t.Run("NoSalt", func(t *testing.T) {
		if err := cmdKdfPbkdf2([]string{"-key=0011"}); err == nil {
			t.Fatal("expected and error")
		}
	})
	t.Run("SaltAsHexAndFromFile", func(t *testing.T) {
		if err := cmdKdfPbkdf2([]string{"-key=0011", "-salt=0011", "-salt-file=foo"}); err == nil {
			t.Fatal("expected and error")
		}
	})
	t.Run("InvalidHashFunc", func(t *testing.T) {
		if err := cmdKdfPbkdf2([]string{"-key=0011", "-salt=0011", "-hash=foo"}); err == nil {
			t.Fatal("expected and error")
		}
	})
}
