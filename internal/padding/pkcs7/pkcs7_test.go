package pkcs7

import (
	"bytes"
	"testing"
)

const bs = 16

func TestPKCS7(t *testing.T) {

	input := []byte{1, 2, 3, 4, 5}
	expectedPadded := []byte{1, 2, 3, 4, 5, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11}

	padded := Pad(bs, input)
	t.Log(padded)

	if !bytes.Equal(padded, expectedPadded) {
		t.Fatal("padded != expectedpadded")
	}

	unpadded, err := Unpad(bs, padded)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(unpadded)

	if !bytes.Equal(unpadded, input) {
		t.Fatal("unpadded != input")
	}
}

func TestPKCS7Errors(t *testing.T) {
	t.Run("OutOfRange", func(t *testing.T) {
		_, err := Unpad(bs, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 42})
		t.Log(err)
		if err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("PaddingNotEqual", func(t *testing.T) {
		_, err := Unpad(bs, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 5})
		t.Log(err)
		if err == nil {
			t.Fatal("expected error")
		}
	})
}
