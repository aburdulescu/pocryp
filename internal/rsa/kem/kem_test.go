package kem

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"

	"bandr.me/p/pocryp/internal/rsa/util"
)

func TestRsaKemEncapsulate(t *testing.T) {
	k := []byte("yellow submarine")

	privateKey, err := util.PrivateKeyFromPem(readFile(t, "testdata/rsa2048_private_key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := util.PublicKeyFromPem(readFile(t, "testdata/rsa2048_public_key.pem"))
	if err != nil {
		t.Fatal(err)
	}

	kdfParams := KDFParams{
		Salt:     []byte{0, 1, 2, 3, 4, 5},
		Iter:     10,
		KeyLen:   32,
		HashFunc: sha256.New,
	}

	ek, err := Encapsulate(publicKey, k, kdfParams)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(hex.EncodeToString(ek))

	actualK, err := Decapsulate(privateKey, ek, kdfParams)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(k, actualK) {
		t.Logf("%s", actualK)
		t.Fatal("not equal")
	}
}

func readFile(t testing.TB, s string) []byte {
	r, err := os.ReadFile(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
