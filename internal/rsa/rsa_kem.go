package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"hash"
	"math/big"

	"bandr.me/p/pocryp/internal/aes"
	"bandr.me/p/pocryp/internal/util"
	"golang.org/x/crypto/pbkdf2"
)

func rsaKemGenerateZ(pubKey *rsa.PublicKey) (*big.Int, error) {
	nLen := util.BitLenToByteLen(pubKey.N.BitLen())

	zBytes := make([]byte, nLen)
	if _, err := rand.Read(zBytes); err != nil {
		return nil, err
	}

	z := new(big.Int)
	z.SetBytes(zBytes)

	// make sure z is < pubkey.N
	z.Mod(z, pubKey.N)

	return z, nil
}

type KDFParams struct {
	Salt     []byte
	Iter     int
	KeyLen   int
	HashFunc func() hash.Hash
}

// Implement sender's operations as described in RFC5990 A.2
func KemEncapsulate(pubKey *rsa.PublicKey, K []byte, kdfParams KDFParams) ([]byte, error) {
	// z = RandomInteger (0, n-1)
	z, err := rsaKemGenerateZ(pubKey)
	if err != nil {
		return nil, err
	}

	// Z = IntegerToString (z, nLen)
	Z := z.Bytes()

	// c = z^e mod n
	c := new(big.Int)
	e := big.NewInt(int64(pubKey.E))
	c.Exp(z, e, pubKey.N)

	// C = IntegerToString (c, nLen)
	C := c.Bytes()

	// KEK = KDF (Z, kekLen)
	KEK := pbkdf2.Key([]byte(Z), kdfParams.Salt, kdfParams.Iter, kdfParams.KeyLen, kdfParams.HashFunc)

	// WK = Wrap (KEK, K)
	WK, err := aes.KeyWrap(KEK, K)
	if err != nil {
		return nil, err
	}

	// EK = C || WK
	EK := make([]byte, len(C)+len(WK))
	if err := util.Concat(EK, []byte(C), WK); err != nil {
		return nil, err
	}

	return EK, err
}

func KemDecapsulate(privKey *rsa.PrivateKey, EK []byte, kdfParams KDFParams) ([]byte, error) {
	nLen := util.BitLenToByteLen(privKey.N.BitLen())

	if len(EK) < nLen {
		return nil, errors.New("decryption error: len(EK) < nLen")
	}

	// C || WK = EK
	C := EK[:nLen]
	WK := EK[nLen:]

	// c = StringToInteger (C)
	c := new(big.Int)
	c.SetBytes(C)
	if zero := big.NewInt(0); c.Cmp(zero) < 0 {
		return nil, errors.New("decryption error: c < 0")
	}
	if c.Cmp(privKey.N) >= 0 {
		return nil, errors.New("decryption error: c >= n")
	}

	// z = c^d mod n
	z := new(big.Int)
	z.Exp(c, privKey.D, privKey.N)

	// Z = IntegerToString (z, nLen)
	Z := z.Bytes()

	// KEK = KDF (Z, kekLen)
	KEK := pbkdf2.Key([]byte(Z), kdfParams.Salt, kdfParams.Iter, kdfParams.KeyLen, kdfParams.HashFunc)

	// K = Unwrap (KEK, WK)
	K, err := aes.KeyUnwrap(KEK, WK)
	if err != nil {
		return nil, fmt.Errorf("decryption error: unwrap: %v", err)
	}

	return K, nil
}
