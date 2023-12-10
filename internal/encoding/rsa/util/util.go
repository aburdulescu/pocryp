package util

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
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func PublicKeyFromPem(p []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(p)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}
	return x509.ParsePKCS1PublicKey(block.Bytes)
}
