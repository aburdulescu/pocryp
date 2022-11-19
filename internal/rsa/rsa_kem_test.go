package rsa

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"bandr.me/p/pocryp/internal/testutil"
)

func TestRsaKemEncapsulate(t *testing.T) {
	k := []byte("yellow submarine")

	privateKey, err := PrivateKeyFromPem(testutil.ReadFile(t, "testdata/rsa2048_private_key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := PublicKeyFromPem(testutil.ReadFile(t, "testdata/rsa2048_public_key.pem"))
	if err != nil {
		t.Fatal(err)
	}

	kdfParams := KDFParams{
		Salt:     []byte{0, 1, 2, 3, 4, 5},
		Iter:     10,
		KeyLen:   32,
		HashFunc: sha256.New,
	}

	ek, err := KemEncapsulate(publicKey, k, kdfParams)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(hex.EncodeToString(ek))

	actualK, err := KemDecapsulate(privateKey, ek, kdfParams)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(k, actualK) {
		t.Logf("%s", actualK)
		t.Fatal("not equal")
	}
}
