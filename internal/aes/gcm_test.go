package aes

import (
	"bytes"
	"encoding/hex"
	"testing"

	"bandr.me/p/pocryp/internal/testutil"
)

func TestGCMEncrypt(t *testing.T) {
	key := testutil.BytesFromHex(t, "7fddb57453c241d03efbed3ac44e371c")
	nonce := testutil.BytesFromHex(t, "ee283a3fc75575e33efd4887")
	plaintext := testutil.BytesFromHex(t, "d5de42b461646c255c87bd2962d3b9a2")
	ciphertext := testutil.BytesFromHex(t, "2ccda4a5415cb91e135c2a0f78c9b2fd")
	tag := testutil.BytesFromHex(t, "b36d1df9b9d5e596f83e8b7f52971cb3")

	var expectedOuput []byte
	expectedOuput = append(expectedOuput, ciphertext...)
	expectedOuput = append(expectedOuput, tag...)

	out, err := GCMEncypt(key, nonce, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, expectedOuput) {
		t.Log(hex.EncodeToString(expectedOuput))
		t.Log(hex.EncodeToString(out))
		t.Fatal("not equal")
	}
}
