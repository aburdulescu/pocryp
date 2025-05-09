package main

import (
	"fmt"
	"os"

	"bandr.me/p/pocryp/internal/aes"
	"bandr.me/p/pocryp/internal/cli"
	"bandr.me/p/pocryp/internal/hash"
	"bandr.me/p/pocryp/internal/kdf"
	"bandr.me/p/pocryp/internal/keygen"

	"bandr.me/p/pocryp/internal/dsa"
	encoding_rsa "bandr.me/p/pocryp/internal/encoding/rsa"
	kem_rsa "bandr.me/p/pocryp/internal/kem/rsa/cmd"
	keywrap_aes "bandr.me/p/pocryp/internal/keywrap/aes/cmd"
	"bandr.me/p/pocryp/internal/misc"
	padding_pkcs7 "bandr.me/p/pocryp/internal/padding/pkcs7/cmd"
	she "bandr.me/p/pocryp/internal/she/cmd"
)

func main() {
	var a cli.App

	a.Add(
		"Key Generation",
		keygen.AesCmd,
		keygen.RsaCmd,
		keygen.RsaGetPubCmd,
		keygen.Ed25519Cmd,
		keygen.Ed25519GetPubCmd,
	)

	a.Add(
		"Key Encoding",
		encoding_rsa.Raw2DerCmd,
		encoding_rsa.Der2RawCmd,
		encoding_rsa.Pem2DerCmd,
		encoding_rsa.Der2PemCmd,
	)

	a.Add(
		"Block Cipher",
		aes.EcbCmd,
	)

	a.Add(
		"Stream Cipher",
		aes.CbcCmd,
	)

	a.Add(
		"Message Authentication Code(MAC)",
		aes.CmacGenerateCmd,
		aes.CmacVerifyCmd,
	)

	a.Add(
		"Authenticated Encryption(AEAD)",
		aes.GcmCmd,
	)

	a.Add(
		"Key Wrap",
		keywrap_aes.Cmd,
	)

	a.Add(
		"Key Derivation Function(KDF)",
		kdf.Pbkdf2Cmd,
	)

	a.Add(
		"Hash Function",
		hash.ShaCmd,
	)

	a.Add(
		"Digital Signature",
		dsa.Ed25519SignCmd,
		dsa.Ed25519VerifyCmd,
	)

	a.Add(
		"Key Encapsulation Mechanism(KEM)",
		kem_rsa.Cmd,
	)

	a.Add(
		"Secured Hardware Extensions(AUTOSAR)",
		she.ExampleCmd,
		she.EncodeCmd,
		she.DecodeCmd,
	)

	a.Add(
		"Padding",
		padding_pkcs7.Cmd,
	)

	a.Add(
		"Miscellaneous",
		misc.Base64Cmd,
		misc.HexCmd,
	)

	if err := a.Run(os.Args[1:]...); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
