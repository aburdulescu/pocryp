package main

import (
	"fmt"
	"os"
)

func main() {
	var app App

	app.Add("AES", Command{
		"aes-keygen", "Generate AES key", cmdAesKeyGen,
	})
	app.Add("AES", Command{
		"aes-ecb", "Encrypt/Decrypt using AES-ECB", cmdAesEcb,
	})
	app.Add("AES", Command{
		"aes-cbc", "Encrypt/Decrypt using AES-CBC", cmdAesCbc,
	})
	app.Add("AES", Command{
		"aes-gcm", "Encrypt/Decrypt using AES-GCM", cmdAesGcm,
	})
	app.Add("AES", Command{
		"aes-keywrap", "Wrap/Unwrap using AES-KEYWRAP", cmdAesKeywrap,
	})

	app.Add("RSA", Command{
		"rsa-keygen", "Generate RSA key", cmdRsaKeyGen,
	})

	app.Add("RSA", Command{
		"rsa-kem", "Encapsulate/Decapsulate using RSA-KEM", cmdRsaKem,
	})
	app.Add("RSA", Command{
		"rsa-raw-der", "Convert RSA key from raw values(n, e, d, p, q) to PKCS#1 ASN.1 DER", cmdRsaRawDer,
	})
	app.Add("RSA", Command{
		"rsa-der-raw", "Convert RSA key from PKCS#1 ASN.1 DER to raw values(n, e, d, p, q)", cmdRsaDerRaw,
	})
	app.Add("RSA", Command{
		"rsa-pem-der", "Convert RSA key from PEM to PKCS#1 ASN.1 DER", cmdRsaPemDer,
	})
	app.Add("RSA", Command{
		"rsa-der-pem", "Convert RSA key from PKCS#1 ASN.1 DER to PEM", cmdRsaDerPem,
	})

	app.Add("KDF", Command{
		"kdf-pbkdf2", "", cmdKdfPbkdf2,
	})

	app.Add("HASH", Command{
		"hash-sha", "", cmdHashSha,
	})

	if err := app.Run(os.Args); err != nil {
		die("%v", err)
	}
}

func die(format string, args ...any) {
	fmt.Fprintln(os.Stderr, "error:", fmt.Sprintf(format, args...))
	os.Exit(1)
}
