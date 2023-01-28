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

	a.Add("aes", app.Command{
		Name:  "keygen",
		Usage: "Generate AES key",
		Run:   aes.KeyGen,
	})
	a.Add("aes", app.Command{
		Name:  "ecb",
		Usage: "Encrypt/Decrypt using AES-ECB",
		Run:   aes.EcbCmd,
	})
	a.Add("aes", app.Command{
		Name:  "cbc",
		Usage: "Encrypt/Decrypt using AES-CBC",
		Run:   aes.CbcCmd,
	})
	a.Add("aes", app.Command{
		Name:  "gcm",
		Usage: "Encrypt/Decrypt using AES-GCM",
		Run:   aes.Gcm,
	})
	a.Add("aes", app.Command{
		Name:  "keywrap",
		Usage: "Wrap/Unwrap using AES-KEYWRAP",
		Run:   aes.KeyWrapCmd,
	})

	a.Add("rsa", app.Command{
		Name:  "keygen",
		Usage: "Generate RSA key",
		Run:   rsa.KeyGenCmd,
	})
	a.Add("rsa", app.Command{
		Name:  "pub-from-priv",
		Usage: "Extract RSA public key from private key",
		Run:   rsa.PubFromPrivCmd,
	})
	a.Add("rsa", app.Command{
		Name:  "kem",
		Usage: "Encapsulate/Decapsulate using RSA-KEM",
		Run:   rsa.KemCmd,
	})
	a.Add("rsa", app.Command{
		Name:  "raw-der",
		Usage: "Convert RSA key from raw values(n, e, d, p, q) to PKCS#1 ASN.1 DER",
		Run:   rsa.RawDerCmd,
	})
	a.Add("rsa", app.Command{
		Name:  "der-raw",
		Usage: "Convert RSA key from PKCS#1 ASN.1 DER to raw values(n, e, d, p, q)",
		Run:   rsa.DerRawCmd,
	})
	a.Add("rsa", app.Command{
		Name:  "pem-der",
		Usage: "Convert RSA key from PEM to PKCS#1 ASN.1 DER",
		Run:   rsa.PemDerCmd,
	})
	a.Add("rsa", app.Command{
		Name:  "der-pem",
		Usage: "Convert RSA key from PKCS#1 ASN.1 DER to PEM",
		Run:   rsa.DerPemCmd,
	})

	a.Add("kdf", app.Command{
		Name:  "pbkdf2",
		Usage: "Derive key using PBKDF2",
		Run:   kdf.Pbkdf2Cmd,
	})

	a.Add("hash", app.Command{
		Name:  "sha",
		Usage: "Generate cryptographic hash using SHA",
		Run:   hash.ShaCmd,
	})

	if err := a.Run(os.Args[1:]); err != nil {
		die("%v", err)
	}
}

func die(format string, args ...any) {
	fmt.Fprintln(os.Stderr, "error:", fmt.Sprintf(format, args...))
	os.Exit(1)
}
