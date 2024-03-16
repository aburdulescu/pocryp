package mp

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestErrors(t *testing.T) {
	t.Run("Compress", func(t *testing.T) {
		t.Run("KeyNotAlignedToBlock", func(t *testing.T) {
			_, err := Compress([]byte{1, 2}, nil)
			if err == nil {
				t.Fatal("expected error")
			}
		})

		t.Run("ConstNotAlignedToBlock", func(t *testing.T) {
			_, err := Compress(make([]byte, bs), []byte{1, 2})
			if err == nil {
				t.Fatal("expected error")
			}
		})
	})

	t.Run("xor3", func(t *testing.T) {
		t.Run("DiffLens01", func(t *testing.T) {
			defer func() {
				v := recover()
				if v == nil {
					t.Fatal("expected error")
				}
			}()
			xor3([]byte{1}, []byte{1, 2}, nil)
		})
		t.Run("DiffLens02", func(t *testing.T) {
			defer func() {
				v := recover()
				if v == nil {
					t.Fatal("expected error")
				}
			}()
			xor3([]byte{1}, []byte{1}, []byte{1, 2})
		})
	})

	t.Run("encrypt", func(t *testing.T) {
		t.Run("InvalidKeySize", func(t *testing.T) {
			defer func() {
				v := recover()
				if v == nil {
					t.Fatal("expected error")
				}
			}()
			encrypt([]byte{1, 2}, nil)
		})

		t.Run("InvalidInput", func(t *testing.T) {
			defer func() {
				v := recover()
				if v == nil {
					t.Fatal("expected error")
				}
			}()
			encrypt(make([]byte, bs), nil)
		})
	})
}

func TestCompressSHE(t *testing.T) {
	// test vectors from SHE doc
	key := h2b("000102030405060708090a0b0c0d0e0f")
	c1 := h2b("010153484500800000000000000000b0")
	c2 := h2b("010253484500800000000000000000b0")
	expectedK1 := h2b("118a46447a770d87828a69c222e2d17e")
	expectedK2 := h2b("2ebb2a3da62dbd64b18ba6493e9fbe22")

	k1, err := Compress(key, c1)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(expectedK1, k1) {
		t.Fatal("k1 nok")
	}

	k2, err := Compress(key, c2)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(expectedK2, k2) {
		t.Fatal("k2 nok")
	}
}

func TestCompressAES256(t *testing.T) {
	key := h2b("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f")
	c := h2b("010001455854008000000000000000B8")
	out, err := Compress(key, c)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(hex.EncodeToString(out))
}

func h2b(h string) []byte {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	return b
}
