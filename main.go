package main

import (
	"fmt"
	"os"

	"bandr.me/p/pocryp/internal/cmd/aes"
	"bandr.me/p/pocryp/internal/cmd/app"
	"bandr.me/p/pocryp/internal/cmd/hash"
	"bandr.me/p/pocryp/internal/cmd/kdf"
	"bandr.me/p/pocryp/internal/cmd/rsa"
)

func main() {
	var a app.App

	a.Add("AES", app.Command{
		Name:  "aes-keygen",
		Usage: "Generate AES key",
		Run:   aes.KeyGen,
	})
	a.Add("AES", app.Command{
		Name:  "aes-ecb",
		Usage: "Encrypt/Decrypt using AES-ECB",
		Run:   aes.Ecb,
	})
	a.Add("AES", app.Command{
		Name:  "aes-cbc",
		Usage: "Encrypt/Decrypt using AES-CBC",
		Run:   aes.Cbc,
	})
	a.Add("AES", app.Command{
		Name:  "aes-gcm",
		Usage: "Encrypt/Decrypt using AES-GCM",
		Run:   aes.Gcm,
	})
	a.Add("AES", app.Command{
		Name:  "aes-keywrap",
		Usage: "Wrap/Unwrap using AES-KEYWRAP",
		Run:   aes.Keywrap,
	})

	a.Add("RSA", app.Command{
		Name:  "rsa-keygen",
		Usage: "Generate RSA key",
		Run:   rsa.KeyGen,
	})
	a.Add("RSA", app.Command{
		Name:  "rsa-pub-from-priv",
		Usage: "Extract RSA public key from private key",
		Run:   rsa.PubFromPriv,
	})
	a.Add("RSA", app.Command{
		Name:  "rsa-kem",
		Usage: "Encapsulate/Decapsulate using RSA-KEM",
		Run:   rsa.Kem,
	})
	a.Add("RSA", app.Command{
		Name:  "rsa-raw-der",
		Usage: "Convert RSA key from raw values(n, e, d, p, q) to PKCS#1 ASN.1 DER",
		Run:   rsa.RawDer,
	})
	a.Add("RSA", app.Command{
		Name:  "rsa-der-raw",
		Usage: "Convert RSA key from PKCS#1 ASN.1 DER to raw values(n, e, d, p, q)",
		Run:   rsa.DerRaw,
	})
	a.Add("RSA", app.Command{
		Name:  "rsa-pem-der",
		Usage: "Convert RSA key from PEM to PKCS#1 ASN.1 DER",
		Run:   rsa.PemDer,
	})
	a.Add("RSA", app.Command{
		Name:  "rsa-der-pem",
		Usage: "Convert RSA key from PKCS#1 ASN.1 DER to PEM",
		Run:   rsa.DerPem,
	})

	a.Add("KDF", app.Command{
		Name:  "kdf-pbkdf2",
		Usage: "Derive key using PBKDF2",
		Run:   kdf.Pbkdf2,
	})

	a.Add("HASH", app.Command{
		Name:  "hash-sha",
		Usage: "Generate cryptographic hash using SHA",
		Run:   hash.Sha,
	})

	if err := a.Run(os.Args[1:]); err != nil {
		die("%v", err)
	}
}

func die(format string, args ...any) {
	fmt.Fprintln(os.Stderr, "error:", fmt.Sprintf(format, args...))
	os.Exit(1)
}
