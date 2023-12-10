package rsa

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"math/big"
	"os"

	"bandr.me/p/pocryp/internal/common"
	"bandr.me/p/pocryp/internal/keywrap/aes"
	"bandr.me/p/pocryp/internal/util"

	rsautil "bandr.me/p/pocryp/internal/rsa/util"

	"golang.org/x/crypto/pbkdf2"
)

func Cmd(args ...string) error {
	fset := flag.NewFlagSet("kem-rsa", flag.ContinueOnError)
	fset.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: pocryp kem-rsa [-e/-d] -key [-in INPUT] [-out OUTPUT]

Encapsulate/Decapsulate INPUT to OUTPUT using RSA-KEM.

If -in is not specified, stdin will be read.
If -out is not specified, the output will be printed to stdout.

Options:
`)
		fset.PrintDefaults()
	}

	fEncapsulate := fset.Bool("e", false, "Encapsulate the input to the output. Default if omitted.")
	fDecapsulate := fset.Bool("d", false, "Decapsulate the input to the output.")
	fOutput := fset.String("out", "", "Write the result to the file at path OUTPUT.")
	fInput := fset.String("in", "", "Read data from the file at path INPUT.")
	fKey := fset.String("key", "", "Path to file which contains the key in PEM format")
	fKdfSalt := fset.String("kdf-salt", "", "KDF salt as hex.")
	fKdfIter := fset.Int("kdf-iter", 5, "KDF iterations.")
	fKdfKeyLen := fset.Int("kdf-key-len", 16, "KDF key length.")
	fKdfHashFunc := fset.String(
		"kdf-hash-func",
		common.AlgSHA256,
		fmt.Sprintf("KDF hash function(valid options: %s).", common.SHAAlgs),
	)

	if err := fset.Parse(args); err != nil {
		return err
	}

	if *fKey == "" {
		fset.Usage()
		return errors.New("no key specified, use -key to specify it")
	}

	keyData, err := os.ReadFile(*fKey)
	if err != nil {
		return err
	}
	var key any
	switch {
	case *fDecapsulate:
		key, err = rsautil.PrivateKeyFromPem(keyData)
		if err != nil {
			return err
		}
	default:
		key, err = rsautil.PublicKeyFromPem(keyData)
		if err != nil {
			return err
		}
	}

	if *fKdfSalt == "" {
		fset.Usage()
		return errors.New("KDF salt cannot be empty")
	}
	kdfSalt, err := hex.DecodeString(*fKdfSalt)
	if err != nil {
		return err
	}

	kdfHashFunc, err := common.HashFuncFrom(*fKdfHashFunc)
	if err != nil {
		fset.Usage()
		return err
	}

	kdfParams := KDFParams{
		Salt:     kdfSalt,
		Iter:     *fKdfIter,
		KeyLen:   *fKdfKeyLen,
		HashFunc: kdfHashFunc,
	}

	var r io.Reader
	if *fInput == "" {
		r = os.Stdin
	} else {
		f, err := os.Open(*fInput)
		if err != nil {
			return err
		}
		defer f.Close()
		r = f
	}

	var w io.Writer
	if *fOutput == "" {
		w = os.Stdout
	} else {
		f, err := os.Create(*fOutput)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}

	var input bytes.Buffer
	if _, err := io.Copy(&input, r); err != nil {
		return err
	}

	var output []byte
	switch {
	case *fEncapsulate:
		output, err = Encapsulate(key.(*rsa.PublicKey), input.Bytes(), kdfParams)
	case *fDecapsulate:
		output, err = Decapsulate(key.(*rsa.PrivateKey), input.Bytes(), kdfParams)
	default:
		output, err = Encapsulate(key.(*rsa.PublicKey), input.Bytes(), kdfParams)
	}
	if err != nil {
		return err
	}

	if _, err := io.Copy(w, bytes.NewBuffer(output)); err != nil {
		return err
	}

	return nil
}

func generateZ(pubKey *rsa.PublicKey) (*big.Int, error) {
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
	HashFunc func() hash.Hash
	Salt     []byte
	Iter     int
	KeyLen   int
}

// Implement sender's operations as described in RFC5990 A.2
func Encapsulate(pubKey *rsa.PublicKey, k []byte, kdfParams KDFParams) ([]byte, error) {
	// z = RandomInteger (0, n-1)
	z, err := generateZ(pubKey)
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
	KEK := pbkdf2.Key(Z, kdfParams.Salt, kdfParams.Iter, kdfParams.KeyLen, kdfParams.HashFunc)

	// WK = Wrap (KEK, K)
	WK, err := aes.Wrap(KEK, k)
	if err != nil {
		return nil, err
	}

	// EK = C || WK
	ek := make([]byte, len(C)+len(WK))
	if err := util.Concat(ek, C, WK); err != nil {
		return nil, err
	}

	return ek, err
}

func Decapsulate(privKey *rsa.PrivateKey, ek []byte, kdfParams KDFParams) ([]byte, error) {
	nLen := util.BitLenToByteLen(privKey.N.BitLen())

	if len(ek) < nLen {
		return nil, errors.New("decryption error: len(EK) < nLen")
	}

	// C || WK = EK
	C := ek[:nLen]
	WK := ek[nLen:]

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
	KEK := pbkdf2.Key(Z, kdfParams.Salt, kdfParams.Iter, kdfParams.KeyLen, kdfParams.HashFunc)

	// K = Unwrap (KEK, WK)
	K, err := aes.Unwrap(KEK, WK)
	if err != nil {
		return nil, fmt.Errorf("decryption error: unwrap: %w", err)
	}

	return K, nil
}
