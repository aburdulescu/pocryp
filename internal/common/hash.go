package common

import (
	// #nosec
	"crypto/sha1"

	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"

	"golang.org/x/crypto/sha3"
)

const (
	AlgSHA1       = "SHA-1"
	AlgSHA224     = "SHA-224"
	AlgSHA256     = "SHA-256"
	AlgSHA384     = "SHA-384"
	AlgSHA512     = "SHA-512"
	AlgSHA512_224 = "SHA-512/224"
	AlgSHA512_256 = "SHA-512/256"
	AlgSHA3_224   = "SHA3-224"
	AlgSHA3_256   = "SHA3-256"
	AlgSHA3_384   = "SHA3-384"
	AlgSHA3_512   = "SHA3-512"
)

const SHAAlgs = AlgSHA1 + ";" +
	AlgSHA224 + ";" +
	AlgSHA256 + ";" +
	AlgSHA384 + ";" +
	AlgSHA512 + ";" +
	AlgSHA512_224 + ";" +
	AlgSHA512_256 + ";" +
	AlgSHA3_224 + ";" +
	AlgSHA3_256 + ";" +
	AlgSHA3_384 + ";" +
	AlgSHA3_512

func HashFuncFrom(str string) (func() hash.Hash, error) {
	switch str {
	case AlgSHA1:
		// #nosec
		return sha1.New, nil
	case AlgSHA224:
		return sha256.New224, nil
	case AlgSHA256:
		return sha256.New, nil
	case AlgSHA384:
		return sha512.New384, nil
	case AlgSHA512:
		return sha512.New, nil
	case AlgSHA512_224:
		return sha512.New512_224, nil
	case AlgSHA512_256:
		return sha512.New512_256, nil
	case AlgSHA3_224:
		return sha3.New224, nil
	case AlgSHA3_256:
		return sha3.New256, nil
	case AlgSHA3_384:
		return sha3.New384, nil
	case AlgSHA3_512:
		return sha3.New512, nil
	default:
		return nil, errors.New("hash alg is not valid")
	}
}
