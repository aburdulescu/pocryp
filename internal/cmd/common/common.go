package common

import (
	// #nosec
	"crypto/sha1"

	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
)

const (
	AlgSHA1   = "SHA-1"
	AlgSHA224 = "SHA-224"
	AlgSHA256 = "SHA-256"
	AlgSHA384 = "SHA-384"
	AlgSHA512 = "SHA-512"
)

const SHAAlgs = AlgSHA1 + "/" + AlgSHA224 + "/" + AlgSHA256 + "/" + AlgSHA384 + "/" + AlgSHA512

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
	default:
		return nil, errors.New("hash alg is not valid")
	}
}
