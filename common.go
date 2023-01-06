package main

import (
	// #nosec
	"crypto/sha1"

	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
)

const (
	algSHA1   = "SHA-1"
	algSHA224 = "SHA-224"
	algSHA256 = "SHA-256"
	algSHA384 = "SHA-384"
	algSHA512 = "SHA-512"
)

const shaAlgs = algSHA1 + "/" + algSHA224 + "/" + algSHA256 + "/" + algSHA384 + "/" + algSHA512

func hashFuncFromStr(str string) (func() hash.Hash, error) {
	switch str {
	case algSHA1:
		// #nosec
		return sha1.New, nil
	case algSHA224:
		return sha256.New224, nil
	case algSHA256:
		return sha256.New, nil
	case algSHA384:
		return sha512.New384, nil
	case algSHA512:
		return sha512.New, nil
	default:
		return nil, errors.New("hash alg is not valid")
	}
}
