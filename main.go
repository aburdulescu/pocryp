package main

import (
	"fmt"
	"os"
)

func main() {
	var app App

	app.Add("AES", Command{
		name: "aes-keygen", usage: "Generate AES key", run: cmdAesKeyGen,
	})
	app.Add("AES", Command{
		name: "aes-ecb", usage: "Encrypt/Decrypt using AES-ECB", run: cmdAesEcb,
	})
	app.Add("AES", Command{
		name: "aes-cbc", usage: "Encrypt/Decrypt using AES-CBC", run: cmdAesCbc,
	})
	app.Add("AES", Command{
		name: "aes-gcm", usage: "Encrypt/Decrypt using AES-GCM", run: cmdAesGcm,
	})
	app.Add("AES", Command{
		name: "aes-keywrap", usage: "Wrap/Unwrap using AES-KEYWRAP", run: cmdAesKeywrap,
	})

	app.Add("RSA", Command{
		name: "rsa-keygen", usage: "Generate RSA key", run: cmdRsaKeyGen,
	})

	app.Add("RSA", Command{
		name: "rsa-kem", usage: "Encapsulate/Decapsulate using RSA-KEM", run: cmdRsaKem,
	})
	app.Add("RSA", Command{
		name: "rsa-raw-der", usage: "Convert RSA key from raw values(n, e, d, p, q) to PKCS#1 ASN.1 DER", run: cmdRsaRawDer,
	})
	app.Add("RSA", Command{
		name: "rsa-der-raw", usage: "Convert RSA key from PKCS#1 ASN.1 DER to raw values(n, e, d, p, q)", run: cmdRsaDerRaw,
	})
	app.Add("RSA", Command{
		name: "rsa-pem-der", usage: "Convert RSA key from PEM to PKCS#1 ASN.1 DER", run: cmdRsaPemDer,
	})
	app.Add("RSA", Command{
		name: "rsa-der-pem", usage: "Convert RSA key from PKCS#1 ASN.1 DER to PEM", run: cmdRsaDerPem,
	})

	app.Add("KDF", Command{
		name: "kdf-pbkdf2", usage: "Derive key using PBKDF2", run: cmdKdfPbkdf2,
	})

	app.Add("HASH", Command{
		name: "hash-sha", usage: "Generate cryptographic hash using SHA", run: cmdHashSha,
	})

	if err := app.Run(os.Args[1:]); err != nil {
		die("%v", err)
	}
}

func die(format string, args ...any) {
	fmt.Fprintln(os.Stderr, "error:", fmt.Sprintf(format, args...))
	os.Exit(1)
}
