package main

import (
	"fmt"
	"os"

	"bandr.me/p/pocryp/internal/aes"
	"bandr.me/p/pocryp/internal/app"
	"bandr.me/p/pocryp/internal/hash"
	"bandr.me/p/pocryp/internal/kdf"
	"bandr.me/p/pocryp/internal/keygen"

	encoding_rsa "bandr.me/p/pocryp/internal/encoding/rsa"
	kem_rsa_cmd "bandr.me/p/pocryp/internal/kem/rsa/cmd"
	keywrap_aes_cmd "bandr.me/p/pocryp/internal/keywrap/aes/cmd"
)

func main() {
	var a app.App

	a.Add(
		"Key Generation",
		app.Command{
			Name:  "gen-aes",
			Usage: "Generate AES key",
			Run:   keygen.Aes,
		},
		app.Command{
			Name:  "gen-rsa",
			Usage: "Generate RSA key",
			Run:   keygen.Rsa,
		},
		app.Command{
			Name:  "gen-ed25519",
			Usage: "Generate ED25519 key",
			Run:   keygen.Ed25519,
		},
	)

	a.Add(
		"Key Encoding",
		app.Command{
			Name:  "rsa-priv2pub",
			Usage: "Extract RSA public key from private key",
			Run:   encoding_rsa.Priv2PubCmd,
		},
		app.Command{
			Name:  "rsa-raw2der",
			Usage: "Convert RSA key from raw values(n, e, d, p, q) to PKCS#1 ASN.1 DER",
			Run:   encoding_rsa.Raw2DerCmd,
		}, app.Command{
			Name:  "rsa-der2raw",
			Usage: "Convert RSA key from PKCS#1 ASN.1 DER to raw values(n, e, d, p, q)",
			Run:   encoding_rsa.Der2RawCmd,
		}, app.Command{
			Name:  "rsa-pem2der",
			Usage: "Convert RSA key from PEM to PKCS#1 ASN.1 DER",
			Run:   encoding_rsa.Pem2DerCmd,
		}, app.Command{
			Name:  "rsa-der2pem",
			Usage: "Convert RSA key from PKCS#1 ASN.1 DER to PEM",
			Run:   encoding_rsa.Der2PemCmd,
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
		"Message Authentication Code(MAC)",
		app.Command{
			Name:  "aes-cmac-generate",
			Usage: "Generate MAC using AES-CMAC",
			Run:   aes.CmacGenerateCmd,
		},
		app.Command{
			Name:  "aes-cmac-verify",
			Usage: "Verify MAC using AES-CMAC",
			Run:   aes.CmacVerifyCmd,
		},
	)

	a.Add(
		"Authenticated Encryption(AEAD)",
		app.Command{
			Name:  "aes-gcm",
			Usage: "Encrypt/Decrypt using AES-GCM",
			Run:   aes.GcmCmd,
		},
	)

	a.Add(
		"Key Wrap",
		app.Command{
			Name:  "aes-keywrap",
			Usage: "Wrap/Unwrap using AES-KEYWRAP",
			Run:   keywrap_aes_cmd.Run,
		},
	)

	a.Add(
		"Key Derivation Function(KDF)",
		app.Command{
			Name:  "pbkdf2",
			Usage: "Derive key using PBKDF2",
			Run:   kdf.Pbkdf2Cmd,
		},
	)

	a.Add(
		"Hash Function",
		app.Command{
			Name:  "sha",
			Usage: "Generate cryptographic hash using SHA",
			Run:   hash.ShaCmd,
		},
	)

	a.Add(
		"Key Encapsulation Mechanism(KEM)",
		app.Command{
			Name:  "kem-rsa",
			Usage: "Encapsulate/Decapsulate using RSA-KEM",
			Run:   kem_rsa_cmd.Run,
		},
	)

	if err := a.Run(os.Args[1:]...); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
