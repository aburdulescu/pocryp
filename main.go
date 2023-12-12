package main

import (
	"fmt"
	"os"

	"bandr.me/p/pocryp/internal/aes"
	"bandr.me/p/pocryp/internal/cli"
	"bandr.me/p/pocryp/internal/hash"
	"bandr.me/p/pocryp/internal/kdf"
	"bandr.me/p/pocryp/internal/keygen"

	encoding_rsa "bandr.me/p/pocryp/internal/encoding/rsa"
	kem_rsa "bandr.me/p/pocryp/internal/kem/rsa/cmd"
	keywrap_aes "bandr.me/p/pocryp/internal/keywrap/aes/cmd"
)

func main() {
	var a cli.App

	a.Add("Key Generation", keygen.AesCmd, keygen.RsaCmd, keygen.Ed25519Cmd)

	a.Add("Key Encoding", encoding_rsa.Priv2PubCmd)
	// 	app.Command{
	// 		Name:  "rsa-raw2der",
	// 		Usage: "Convert RSA key from raw values(n, e, d, p, q) to PKCS#1 ASN.1 DER",
	// 		Run:   encoding_rsa.Raw2DerCmd,
	// 	}, app.Command{
	// 		Name:  "rsa-der2raw",
	// 		Usage: "Convert RSA key from PKCS#1 ASN.1 DER to raw values(n, e, d, p, q)",
	// 		Run:   encoding_rsa.Der2RawCmd,
	// 	}, app.Command{
	// 		Name:  "rsa-pem2der",
	// 		Usage: "Convert RSA key from PEM to PKCS#1 ASN.1 DER",
	// 		Run:   encoding_rsa.Pem2DerCmd,
	// 	}, app.Command{
	// 		Name:  "rsa-der2pem",
	// 		Usage: "Convert RSA key from PKCS#1 ASN.1 DER to PEM",
	// 		Run:   encoding_rsa.Der2PemCmd,
	// 	},

	a.Add("Block Cipher", aes.EcbCmd)

	// a.Add(
	// 	"Stream Cipher",
	// 	app.Command{
	// 		Name:  "aes-cbc",
	// 		Usage: "Encrypt/Decrypt using AES-CBC",
	// 		Run:   aes.CbcCmd,
	// 	},
	// )

	// a.Add(
	// 	"Message Authentication Code(MAC)",
	// 	app.Command{
	// 		Name:  "aes-cmac-generate",
	// 		Usage: "Generate MAC using AES-CMAC",
	// 		Run:   aes.CmacGenerateCmd,
	// 	},
	// 	app.Command{
	// 		Name:  "aes-cmac-verify",
	// 		Usage: "Verify MAC using AES-CMAC",
	// 		Run:   aes.CmacVerifyCmd,
	// 	},
	// )

	// a.Add(
	// 	"Authenticated Encryption(AEAD)",
	// 	app.Command{
	// 		Name:  "aes-gcm",
	// 		Usage: "Encrypt/Decrypt using AES-GCM",
	// 		Run:   aes.GcmCmd,
	// 	},
	// )

	a.Add("Key Wrap", keywrap_aes.Cmd)
	a.Add("Key Derivation Function(KDF)", kdf.Pbkdf2Cmd)
	a.Add("Hash Function", hash.ShaCmd)
	a.Add("Key Encapsulation Mechanism(KEM)", kem_rsa.Cmd)

	if err := a.Run(os.Args[1:]...); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
