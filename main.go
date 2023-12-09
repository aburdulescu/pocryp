package main

import (
	"fmt"
	"os"

	"bandr.me/p/pocryp/internal/aes"
	"bandr.me/p/pocryp/internal/app"
	"bandr.me/p/pocryp/internal/hash"
	"bandr.me/p/pocryp/internal/kdf"
	"bandr.me/p/pocryp/internal/rsa"
)

func main() {
	var a app.App

	a.Add(
		"Key Generation",
		app.Command{
			Name:  "gen-aes",
			Usage: "Generate AES key",
			Run:   aes.KeyGen,
		},
		app.Command{
			Name:  "gen-rsa",
			Usage: "Generate RSA key",
			Run:   rsa.KeyGenCmd,
		},
	)

	a.Add(
		"Key Encoding",
		app.Command{
			Name:  "rsa-pub-from-priv",
			Usage: "Extract RSA public key from private key",
			Run:   rsa.PubFromPrivCmd,
		},
		app.Command{
			Name:  "rsa-raw-der",
			Usage: "Convert RSA key from raw values(n, e, d, p, q) to PKCS#1 ASN.1 DER",
			Run:   rsa.RawDerCmd,
		}, app.Command{
			Name:  "rsa-der-raw",
			Usage: "Convert RSA key from PKCS#1 ASN.1 DER to raw values(n, e, d, p, q)",
			Run:   rsa.DerRawCmd,
		}, app.Command{
			Name:  "rsa-pem-der",
			Usage: "Convert RSA key from PEM to PKCS#1 ASN.1 DER",
			Run:   rsa.PemDerCmd,
		}, app.Command{
			Name:  "rsa-der-pem",
			Usage: "Convert RSA key from PKCS#1 ASN.1 DER to PEM",
			Run:   rsa.DerPemCmd,
		},
	)

	a.Add(
		"Block Cipher",
		app.Command{
			Name:  "aes-ecb",
			Usage: "Encrypt/Decrypt using AES-ECB",
			Run:   aes.EcbCmd,
		},
	)

	a.Add(
		"Stream Cipher",
		app.Command{
			Name:  "aes-cbc",
			Usage: "Encrypt/Decrypt using AES-CBC",
			Run:   aes.CbcCmd,
		},
	)

	a.Add(
		"AEAD",
		app.Command{
			Name:  "aes-gcm",
			Usage: "Encrypt/Decrypt using AES-GCM",
			Run:   aes.Gcm,
		},
	)

	a.Add(
		"Key Wrap",
		app.Command{
			Name:  "aes-keywrap",
			Usage: "Wrap/Unwrap using AES-KEYWRAP",
			Run:   aes.KeyWrapCmd,
		},
	)

	a.Add(
		"Key Derivation",
		app.Command{
			Name:  "pbkdf2",
			Usage: "Derive key using PBKDF2",
			Run:   kdf.Pbkdf2Cmd,
		},
	)

	a.Add(
		"Hashing",
		app.Command{
			Name:  "sha",
			Usage: "Generate cryptographic hash using SHA",
			Run:   hash.ShaCmd,
		},
	)

	a.Add(
		"Key Encapsulation Mechanism",
		app.Command{
			Name:  "rsa-kem",
			Usage: "Encapsulate/Decapsulate using RSA-KEM",
			Run:   rsa.KemCmd,
		},
	)

	if err := a.Run(os.Args[1:]...); err != nil {
		die("%v", err)
	}
}

func die(format string, args ...any) {
	fmt.Fprintln(os.Stderr, "error:", fmt.Sprintf(format, args...))
	os.Exit(1)
}
