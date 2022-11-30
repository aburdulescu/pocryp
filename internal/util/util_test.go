package util

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestBitLenToByteLen(t *testing.T) {
	tests := []struct {
		input, expected int
	}{
		{1, 1},
		{9, 2},
		{15, 2},
		{31, 4},
		{32, 4},
		{511, 64},
	}
	for i, test := range tests {
		if v := BitLenToByteLen(test.input); v != test.expected {
			t.Fatalf("%d: expected %d, have %d", i, test.expected, v)
		}
	}
}

func TestConcat(t *testing.T) {
	l := []byte{1, 2}
	r := []byte{3, 4}

	if err := Concat(nil, l, r); err == nil {
		t.Fatal("expected error")
	}

	var expected [4]byte
	copy(expected[:], l)
	copy(expected[len(l):], r)

	var dst [4]byte

	if err := Concat(dst[:], l, r); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(dst[:], expected[:]) {
		t.Log(hex.EncodeToString(expected[:]))
		t.Log(hex.EncodeToString(dst[:]))
		t.Fatal("not equal")
	}
}

func TestXor(t *testing.T) {
	if err := Xor(nil, []byte{1}, nil); err == nil {
		t.Fatal("expected error")
	}
	if err := Xor(nil, []byte{1}, []byte{2}); err == nil {
		t.Fatal("expected error")
	}

	tests := []struct {
		expected, l, r []byte
	}{
		{[]byte{0, 0}, []byte{0, 0}, []byte{0, 0}},
		{[]byte{1, 1}, []byte{0, 0}, []byte{1, 1}},
		{[]byte{1, 1}, []byte{1, 1}, []byte{0, 0}},
		{[]byte{0, 0}, []byte{1, 1}, []byte{1, 1}},
		{[]byte{0, 1}, []byte{0, 1}, []byte{0, 0}},
		{[]byte{1, 0}, []byte{0, 0}, []byte{1, 0}},
		{[]byte{1, 1}, []byte{1, 0}, []byte{0, 1}},
		{[]byte{1, 1}, []byte{0, 1}, []byte{1, 0}},
		{[]byte{0, 0}, []byte{0, 1}, []byte{0, 1}},
	}

	var dst [2]byte
	for i, test := range tests {
		if err := Xor(dst[:], test.l, test.r); err != nil {
			t.Fatal(i, err)
		}
		if !bytes.Equal(dst[:], test.expected) {
			t.Fatalf("%d: expected %d, have %d", i, test.expected, dst[:])
		}
	}
}
