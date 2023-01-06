package rsa

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

func PrivateKeyFromPem(p []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(p)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	out, _ := key.(*rsa.PrivateKey)
	return out, nil
}

func PublicKeyFromPem(p []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(p)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	switch key := key.(type) {
	case *rsa.PublicKey:
		return key, nil
	default:
		break // fall through
	}
	return nil, errors.New("Key type is not RSA")
}
