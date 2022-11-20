package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"sort"
	"strconv"
	"strings"

	poaes "bandr.me/p/pocryp/internal/aes"
	porsa "bandr.me/p/pocryp/internal/rsa"
	"golang.org/x/crypto/pbkdf2"
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

	flag.Parse()

	if err := app.Run(flag.Args()); err != nil {
		die("%v", err)
	}
}

type Command struct {
	name  string
	usage string
	run   func([]string) error
}

type Category struct {
	name     string
	commands []Command
}

type App struct {
	categories []Category
}

func (a App) Run(args []string) error {
	if len(args) == 0 {
		a.Usage()
		return nil
	}
	name := args[0]
	args = args[1:]
	for _, category := range a.categories {
		for _, cmd := range category.commands {
			if cmd.name == name {
				return cmd.run(args)
			}
		}
	}
	return fmt.Errorf("unknown command '%s'", name)
}

func (a *App) Add(category string, c Command) {
	i := -1
	for ii, v := range a.categories {
		if v.name == category {
			i = ii
		}
	}
	if i == -1 {
		a.categories = append(a.categories, Category{name: category})
		i = len(a.categories) - 1
	}
	a.categories[i].commands = append(a.categories[i].commands, c)
	sort.Slice(a.categories, func(i, j int) bool {
		return a.categories[i].name < a.categories[j].name
	})
}

func (a App) maxCommandName(category string) int {
	max := 0
	for _, v := range a.categories {
		if v.name != category {
			continue
		}
		for _, cmd := range v.commands {
			if len(cmd.name) > max {
				max = len(cmd.name)
			}
		}
	}
	return max
}

func (a App) Usage() {
	w := os.Stderr
	fmt.Fprint(w, "Usage: pocryp command [ARGS]\n\nCommands:\n\n")
	for _, v := range a.categories {
		fmt.Fprintf(w, "%s:\n", v.name)
		mlen := a.maxCommandName(v.name)
		for _, cmd := range v.commands {
			padding := strings.Repeat(" ", mlen-len(cmd.name))
			fmt.Fprintf(w, "  %s%s  %s\n", cmd.name, padding, cmd.usage)
		}
		fmt.Fprint(w, "\n")
	}
	fmt.Fprint(w, "Run 'pocryp command -h' for more information about a command.\n")
}

func die(format string, args ...any) {
	fmt.Fprintln(os.Stderr, "error:", fmt.Sprintf(format, args...))
	os.Exit(1)
}

func cmdAesEcb(args []string) error {
	fset := flag.NewFlagSet("aes-ecb", flag.ContinueOnError)
	fset.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: pocryp aes-ecb [-e/-d] -key|-key-file [-in INPUT] [-out OUTPUT]

Encrypt/Decrypt INPUT to OUTPUT using AES-ECB.

If -in is not specified, stdin will be read.
If -out is not specified, the output will be printed to stdout.

Options:
`)
		fset.PrintDefaults()
		os.Exit(1)
	}

	fEncrypt := fset.Bool("e", false, "Encrypt the input to the output. Default if omitted.")
	fDecrypt := fset.Bool("d", false, "Decrypt the input to the output.")
	fOutput := fset.String("out", "", "Write the result to the file at path OUTPUT.")
	fInput := fset.String("in", "", "Read data from the file at path INPUT.")
	fKey := fset.String("key", "", "Key as hex.")
	fKeyFile := fset.String("key-file", "", "File which contains the key as binary/text.")

	fset.Parse(args)

	if *fKey == "" && *fKeyFile == "" {
		return errors.New("no key specified, use -key or -key-file to specify it")
	}

	if *fKey != "" && *fKeyFile != "" {
		return errors.New("cannot use -key and -key-file at the same time")
	}

	var key []byte
	if *fKey != "" {
		b, err := hex.DecodeString(*fKey)
		if err != nil {
			return err
		}
		key = b
	}
	if *fKeyFile != "" {
		b, err := ioutil.ReadFile(*fKeyFile)
		if err != nil {
			return err
		}
		key = b
	}

	var r io.Reader
	if *fInput == "" {
		r = os.Stdin
	} else {
		f, err := os.Open(*fInput)
		if err != nil {
			return err
		}
		defer f.Close()
		r = f
	}

	var w io.Writer
	if *fOutput == "" {
		w = os.Stdout
	} else {
		f, err := os.Create(*fOutput)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}

	var input bytes.Buffer
	if _, err := io.Copy(&input, r); err != nil {
		return err
	}

	var err error
	var output []byte
	switch {
	case *fEncrypt:
		output, err = poaes.ECB(key, input.Bytes(), true)
	case *fDecrypt:
		output, err = poaes.ECB(key, input.Bytes(), false)
	default:
		output, err = poaes.ECB(key, input.Bytes(), true)
	}
	if err != nil {
		return err
	}

	if _, err := io.Copy(w, bytes.NewBuffer(output)); err != nil {
		return err
	}

	return nil
}

func cmdAesCbc(args []string) error {
	fset := flag.NewFlagSet("aes-cbc", flag.ContinueOnError)
	fset.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: pocryp aes-cbc [-e/-d] -key/-key-file -iv/-iv-file [-in INPUT] [-out OUTPUT]

Encrypt/Decrypt INPUT to OUTPUT using AES-CBC.

If -in is not specified, stdin will be read.
If -out is not specified, the output will be printed to stdout.

Options:
`)
		fset.PrintDefaults()
		os.Exit(1)
	}

	fEncrypt := fset.Bool("e", false, "Encrypt the input to the output. Default if omitted.")
	fDecrypt := fset.Bool("d", false, "Decrypt the input to the output.")
	fOutput := fset.String("out", "", "Write the result to the file at path OUTPUT.")
	fInput := fset.String("in", "", "Read data from the file at path INPUT.")
	fKey := fset.String("key", "", "Key as hex.")
	fKeyFile := fset.String("key-file", "", "File which contains the key as binary/text.")
	fIV := fset.String("iv", "", "IV as hex.")

	fset.Parse(args)

	if *fKey == "" && *fKeyFile == "" {
		return errors.New("no key specified, use -k or --key-file to specify it")
	}
	if *fKey != "" && *fKeyFile != "" {
		return errors.New("cannot use -k and --key-file at the same time")
	}

	if *fIV == "" {
		return errors.New("no IV specified, use -iv to specify it")
	}

	var key []byte
	if *fKey != "" {
		b, err := hex.DecodeString(*fKey)
		if err != nil {
			return err
		}
		key = b
	}
	if *fKeyFile != "" {
		b, err := ioutil.ReadFile(*fKeyFile)
		if err != nil {
			return err
		}
		key = b
	}

	iv, err := hex.DecodeString(*fIV)
	if err != nil {
		return err
	}

	var r io.Reader
	if *fInput == "" {
		r = os.Stdin
	} else {
		f, err := os.Open(*fInput)
		if err != nil {
			return err
		}
		defer f.Close()
		r = f
	}

	var w io.Writer
	if *fOutput == "" {
		w = os.Stdout
	} else {
		f, err := os.Create(*fOutput)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}

	var input bytes.Buffer
	if _, err := io.Copy(&input, r); err != nil {
		return err
	}

	var c cipher.BlockMode
	switch {
	case *fEncrypt:
		c, err = poaes.NewCBCEncrypter(key, iv)
	case *fDecrypt:
		c, err = poaes.NewCBCDecrypter(key, iv)
	default:
		c, err = poaes.NewCBCEncrypter(key, iv)
	}
	if err != nil {
		return err
	}

	output := poaes.CBCProcessBlocks(c, input.Bytes())

	if _, err := io.Copy(w, bytes.NewBuffer(output)); err != nil {
		return err
	}

	return nil
}

func cmdAesKeywrap(args []string) error {
	fset := flag.NewFlagSet("aes-keywrap", flag.ContinueOnError)
	fset.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: pocryp aes-keywrap [-w/-u] -key/-key-file [-in INPUT] [-out OUTPUT]

Wrap/Unwrap INPUT to OUTPUT using AES-KEYWRAP.

If -in is not specified, stdin will be read.
If -out is not specified, the output will be printed to stdout.

Options:
`)
		fset.PrintDefaults()
		os.Exit(1)
	}

	fWrap := fset.Bool("w", false, "Wrap the input to the output. Default if omitted.")
	fUnwrap := fset.Bool("u", false, "Unwrap the input to the output.")
	fOutput := fset.String("out", "", "Write the result to the file at path OUTPUT.")
	fInput := fset.String("in", "", "Read data from the file at path INPUT.")
	fKey := fset.String("key", "", "Key as hex.")
	fKeyFile := fset.String("key-file", "", "File which contains the key as binary/text.")

	fset.Parse(args)

	if *fKey == "" && *fKeyFile == "" {
		return errors.New("no key specified, use -k or --key-file to specify it")
	}
	if *fKey != "" && *fKeyFile != "" {
		return errors.New("cannot use -k and --key-file at the same time")
	}

	var key []byte
	if *fKey != "" {
		b, err := hex.DecodeString(*fKey)
		if err != nil {
			return err
		}
		key = b
	}
	if *fKeyFile != "" {
		b, err := ioutil.ReadFile(*fKeyFile)
		if err != nil {
			return err
		}
		key = b
	}

	var r io.Reader
	if *fInput == "" {
		r = os.Stdin
	} else {
		f, err := os.Open(*fInput)
		if err != nil {
			return err
		}
		defer f.Close()
		r = f
	}

	var w io.Writer
	if *fOutput == "" {
		w = os.Stdout
	} else {
		f, err := os.Create(*fOutput)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}

	var input bytes.Buffer
	if _, err := io.Copy(&input, r); err != nil {
		return err
	}

	var output []byte
	var err error
	switch {
	case *fWrap:
		output, err = poaes.KeyWrap(key, input.Bytes())
	case *fUnwrap:
		output, err = poaes.KeyUnwrap(key, input.Bytes())
	default:
		output, err = poaes.KeyWrap(key, input.Bytes())
	}
	if err != nil {
		return err
	}

	if _, err := io.Copy(w, bytes.NewBuffer(output)); err != nil {
		return err
	}

	return nil
}

func cmdRsaKem(args []string) error {
	fset := flag.NewFlagSet("rsa-kem", flag.ContinueOnError)
	fset.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: pocryp rsa-kem [-e/-d] -key [-in INPUT] [-out OUTPUT]

Encapsulate/Decapsulate INPUT to OUTPUT using RSA-KEM.

If -in is not specified, stdin will be read.
If -out is not specified, the output will be printed to stdout.

Options:
`)
		fset.PrintDefaults()
		os.Exit(1)
	}

	fEncapsulate := fset.Bool("e", false, "Encapsulate the input to the output. Default if omitted.")
	fDecapsulate := fset.Bool("d", false, "Decapsulate the input to the output.")
	fOutput := fset.String("out", "", "Write the result to the file at path OUTPUT.")
	fInput := fset.String("in", "", "Read data from the file at path INPUT.")
	fKey := fset.String("key", "", "Path to file which contains the key in PEM format")
	fKdfSalt := fset.String("kdf-salt", "", "KDF salt as hex.")
	fKdfIter := fset.Int("kdf-iter", 5, "KDF iterations.")
	fKdfKeyLen := fset.Int("kdf-key-len", 16, "KDF key length.")
	fKdfHashFunc := fset.String("kdf-hash-func", "SHA-256", "KDF hash function(valid options: SHA-1, SHA-224, SHA-256, SHA-384 and SHA-512).")

	fset.Parse(args)

	if *fKey == "" {
		return errors.New("no key specified, use -key to specify it")
	}

	keyData, err := ioutil.ReadFile(*fKey)
	if err != nil {
		return err
	}
	var key any
	switch {
	case *fDecapsulate:
		key, err = porsa.PrivateKeyFromPem(keyData)
		if err != nil {
			return err
		}
	default:
		key, err = porsa.PublicKeyFromPem(keyData)
		if err != nil {
			return err
		}
	}

	if *fKdfSalt == "" {
		return errors.New("KDF salt cannot be empty")
	}
	kdfSalt, err := hex.DecodeString(*fKdfSalt)
	if err != nil {
		return err
	}
	var kdfHashFunc func() hash.Hash
	switch *fKdfHashFunc {
	case "SHA-1":
		kdfHashFunc = sha1.New
	case "SHA-224":
		kdfHashFunc = sha256.New224
	case "SHA-256":
		kdfHashFunc = sha256.New
	case "SHA-384":
		kdfHashFunc = sha512.New384
	case "SHA-512":
		kdfHashFunc = sha512.New
	default:
		return errors.New("KDF hash function is not valid")
	}
	kdfParams := porsa.KDFParams{
		Salt:     kdfSalt,
		Iter:     *fKdfIter,
		KeyLen:   *fKdfKeyLen,
		HashFunc: kdfHashFunc,
	}

	var r io.Reader
	if *fInput == "" {
		r = os.Stdin
	} else {
		f, err := os.Open(*fInput)
		if err != nil {
			return err
		}
		defer f.Close()
		r = f
	}

	var w io.Writer
	if *fOutput == "" {
		w = os.Stdout
	} else {
		f, err := os.Create(*fOutput)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}

	var input bytes.Buffer
	if _, err := io.Copy(&input, r); err != nil {
		return err
	}

	var output []byte
	switch {
	case *fEncapsulate:
		output, err = porsa.KemEncapsulate(key.(*rsa.PublicKey), input.Bytes(), kdfParams)
	case *fDecapsulate:
		output, err = porsa.KemDecapsulate(key.(*rsa.PrivateKey), input.Bytes(), kdfParams)
	default:
		output, err = porsa.KemEncapsulate(key.(*rsa.PublicKey), input.Bytes(), kdfParams)
	}
	if err != nil {
		return err
	}

	if _, err := io.Copy(w, bytes.NewBuffer(output)); err != nil {
		return err
	}

	return nil
}

func cmdRsaRawDer(args []string) error {
	fset := flag.NewFlagSet("rsa-raw-der", flag.ContinueOnError)
	fset.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: pocryp rsa-raw-der [-priv|-pub] -n modulus [-e publicExponent] -d privateExponent [-p prime1 -q prime2]

Convert RSA key from raw values(n, e, d, p, q) to PKCS#1 ASN.1 DER.

Options:
`)
		fset.PrintDefaults()
		os.Exit(1)
	}

	fPriv := fset.Bool("priv", false, "Encode PrivateKey from given inputs.")
	fPub := fset.Bool("pub", false, "Encode PublicKey from given inputs.")
	fMod := fset.String("n", "", "Modulus as hex string")
	fPubExp := fset.Int("e", 0, "Public exponent as integer")
	fPrivExp := fset.String("d", "", "Private exponent as hex string")
	fPrime1 := fset.String("p", "", "First prime number as hex string")
	fPrime2 := fset.String("q", "", "Second prime number as hex string")

	fset.Parse(args)

	if *fMod == "" {
		return errors.New("modulus not specified, use -n to specify it")
	}

	if *fPub && *fPriv {
		return errors.New("cannot specify -priv and -pub at the same time, choose one")
	}

	nBytes, err := hex.DecodeString(*fMod)
	if err != nil {
		return err
	}
	n := new(big.Int)
	n.SetBytes(nBytes)

	var result []byte
	switch {
	case *fPriv:
		if *fPubExp == 0 {
			return errors.New("-e is needed")
		}
		if *fPrivExp == "" {
			return errors.New("-d is needed")
		}
		if *fPrime1 == "" {
			return errors.New("-p is needed")
		}
		if *fPrime2 == "" {
			return errors.New("-q is needed")
		}
		dBytes, err := hex.DecodeString(*fPrivExp)
		if err != nil {
			return err
		}
		d := new(big.Int)
		d.SetBytes(dBytes)
		pBytes, err := hex.DecodeString(*fPrime1)
		if err != nil {
			return err
		}
		p := new(big.Int)
		p.SetBytes(pBytes)
		qBytes, err := hex.DecodeString(*fPrime2)
		if err != nil {
			return err
		}
		q := new(big.Int)
		q.SetBytes(qBytes)
		key := &rsa.PrivateKey{
			PublicKey: rsa.PublicKey{
				N: n,
				E: *fPubExp,
			},
			D:      d,
			Primes: []*big.Int{p, q},
		}
		result = x509.MarshalPKCS1PrivateKey(key)
	case *fPub:
		if *fPubExp == 0 {
			return errors.New("-e is needed")
		}
		key := &rsa.PublicKey{
			N: n,
			E: *fPubExp,
		}
		result = x509.MarshalPKCS1PublicKey(key)
	default:
		return errors.New("need to specify one of -priv or -pub")
	}

	fmt.Println(hex.EncodeToString(result))

	return nil
}

func cmdRsaDerRaw(args []string) error {
	fset := flag.NewFlagSet("rsa-der-raw", flag.ContinueOnError)
	fset.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: pocryp rsa-der-raw -priv/-pub DER

Convert RSA key from PKCS#1 ASN.1 DER to raw values(n, e, d, p, q).

Options:
`)
		fset.PrintDefaults()
		os.Exit(1)
	}

	fPriv := fset.Bool("priv", false, "Encode PrivateKey from given input.")
	fPub := fset.Bool("pub", false, "Encode PublicKey from given input.")

	fset.Parse(args)

	if fset.NArg() != 1 {
		return errors.New("DER hex string not specified")
	}

	input, err := hex.DecodeString(fset.Arg(0))
	if err != nil {
		return err
	}

	switch {
	case *fPriv:
		key, err := x509.ParsePKCS1PrivateKey(input)
		if err != nil {
			return err
		}
		fmt.Printf("n=%s\n", hex.EncodeToString(key.N.Bytes()))
		fmt.Printf("e=%x\n", key.E)
		fmt.Printf("d=%s\n", hex.EncodeToString(key.D.Bytes()))
		fmt.Printf("p=%s\n", hex.EncodeToString(key.Primes[0].Bytes()))
		fmt.Printf("q=%s\n", hex.EncodeToString(key.Primes[1].Bytes()))
	case *fPub:
		key, err := x509.ParsePKCS1PublicKey(input)
		if err != nil {
			return err
		}
		fmt.Printf("n=%s\n", hex.EncodeToString(key.N.Bytes()))
		fmt.Printf("e=%x\n", key.E)
	default:
		return errors.New("need to specify one of -priv or -pub")
	}

	return nil
}

func cmdRsaDerPem(args []string) error {
	fset := flag.NewFlagSet("rsa-der-pem", flag.ContinueOnError)
	fset.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: pocryp rsa-der-pem -priv/-pub [-in INPUT] [-out OUTPUT]

Convert RSA key from PKCS#1 ASN.1 DER to PEM.

If -in is not specified, stdin will be read.
If -out is not specified, the output will be printed to stdout.

Options:
`)
		fset.PrintDefaults()
		os.Exit(1)
	}

	fPriv := fset.Bool("priv", false, "Encode PrivateKey from given input.")
	fPub := fset.Bool("pub", false, "Encode PublicKey from given input.")
	fOutput := fset.String("out", "", "Write the result to the file at path OUTPUT.")
	fInput := fset.String("in", "", "Read data from the file at path INPUT.")

	fset.Parse(args)

	var r io.Reader
	if *fInput == "" {
		r = os.Stdin
	} else {
		f, err := os.Open(*fInput)
		if err != nil {
			return err
		}
		defer f.Close()
		r = f
	}

	var w io.Writer
	if *fOutput == "" {
		w = os.Stdout
	} else {
		f, err := os.Create(*fOutput)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}

	var input bytes.Buffer
	if _, err := io.Copy(&input, r); err != nil {
		return err
	}

	var blockType string
	switch {
	case *fPriv:
		blockType = "RSA PRIVATE KEY"
	case *fPub:
		blockType = "RSA PUBLIC KEY"
	default:
		return errors.New("need to specify one of -priv or -pub")
	}

	block := &pem.Block{
		Type:  blockType,
		Bytes: input.Bytes(),
	}
	if err := pem.Encode(w, block); err != nil {
		return err
	}

	return nil
}

func cmdRsaPemDer(args []string) error {
	fset := flag.NewFlagSet("rsa-pem-der", flag.ContinueOnError)
	fset.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: pocryp rsa-pem-der [-in INPUT] [-out OUTPUT]

Convert RSA key from PEM to PKCS#1 ASN.1 DER.

If -in is not specified, stdin will be read.
If -out is not specified, the output will be printed to stdout.

Options:
`)
		fset.PrintDefaults()
		os.Exit(1)
	}

	fOutput := fset.String("out", "", "Write the result to the file at path OUTPUT.")
	fInput := fset.String("in", "", "Read data from the file at path INPUT.")

	fset.Parse(args)

	var r io.Reader
	if *fInput == "" {
		r = os.Stdin
	} else {
		f, err := os.Open(*fInput)
		if err != nil {
			return err
		}
		defer f.Close()
		r = f
	}

	var w io.Writer
	if *fOutput == "" {
		w = os.Stdout
	} else {
		f, err := os.Create(*fOutput)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}

	var input bytes.Buffer
	if _, err := io.Copy(&input, r); err != nil {
		return err
	}

	block, _ := pem.Decode(input.Bytes())
	if block == nil {
		return errors.New("failed to parse PEM block")
	}

	if _, err := io.Copy(w, bytes.NewBuffer(block.Bytes)); err != nil {
		return err
	}

	return nil
}

func cmdAesKeyGen(args []string) error {
	fset := flag.NewFlagSet("aes-keygen", flag.ContinueOnError)
	fset.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: pocryp aes-keygen [-out OUTPUT] NUM_BITS

Generate AES key.

If -out is not specified, the output will be printed to stdout.

Options:
`)
		fset.PrintDefaults()
		os.Exit(1)
	}

	fOutput := fset.String("out", "", "Write the result to the file at path OUTPUT.")

	fset.Parse(args)

	if fset.NArg() == 0 {
		return errors.New("number of bits not specified")
	}

	numBits, err := strconv.Atoi(fset.Arg(0))
	if err != nil {
		return err
	}

	if !(numBits == 128 || numBits == 192 || numBits == 256) {
		return errors.New("invalid num bits requested")
	}

	numBits /= 8

	output := make([]byte, numBits)
	if _, err := rand.Read(output); err != nil {
		return err
	}

	if *fOutput == "" {
		fmt.Println(hex.EncodeToString(output))
		return nil
	}

	f, err := os.Create(*fOutput)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := io.Copy(f, bytes.NewBuffer(output)); err != nil {
		return err
	}

	return nil
}

func cmdRsaKeyGen(args []string) error {
	fset := flag.NewFlagSet("rsa-keygen", flag.ContinueOnError)
	fset.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: pocryp rsa-keygen [-out OUTPUT] NUM_BITS

Generate RSA key.

If -out is not specified, the output will be printed to stdout.

Options:
`)
		fset.PrintDefaults()
		os.Exit(1)
	}

	fOutput := fset.String("out", "", "Write the result to the file at path OUTPUT.")

	fset.Parse(args)

	if fset.NArg() == 0 {
		return errors.New("number of bits not specified")
	}

	numBits, err := strconv.Atoi(fset.Arg(0))
	if err != nil {
		return err
	}

	if !(numBits == 2048 || numBits == 3072 || numBits == 4096) {
		return errors.New("invalid num bits requested")
	}

	var w io.Writer
	if *fOutput == "" {
		w = os.Stdout
	} else {
		f, err := os.Create(*fOutput)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}

	key, err := rsa.GenerateKey(rand.Reader, numBits)
	if err != nil {
		return err
	}

	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	if err := pem.Encode(w, block); err != nil {
		return err
	}

	return nil
}

func cmdKdfPbkdf2(args []string) error {
	fset := flag.NewFlagSet("kdf-pbkdf2", flag.ContinueOnError)
	fset.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: pocryp kdf-pbkdf2 -key|-key-file -salt|-salt-file -iter -len -hash [-out OUTPUT]

Derive a new key from the given key using PBKDF2.

If -in is not specified, stdin will be read.
If -out is not specified, the output will be printed to stdout.

Options:
`)
		fset.PrintDefaults()
		os.Exit(1)
	}

	fOutput := fset.String("out", "", "Write the result to the file at path OUTPUT.")
	fKey := fset.String("key", "", "Key as hex.")
	fKeyFile := fset.String("key-file", "", "File which contains the key as binary/text.")
	fSalt := fset.String("salt", "", "Salt as hex.")
	fSaltFile := fset.String("salt-file", "", "File which contains the salt as binary/text.")
	fIter := fset.Int("iter", 1024, "Number of iterations.")
	fLen := fset.Int("len", 128, "Bit-length of the derived key.")
	fHashFunc := fset.String("hash", "SHA-1", "Hash function(valid options: SHA-1, SHA-224, SHA-256, SHA-384 and SHA-512).")

	fset.Parse(args)

	if *fKey == "" && *fKeyFile == "" {
		return errors.New("no key specified, use -key or -key-file to specify it")
	}
	if *fKey != "" && *fKeyFile != "" {
		return errors.New("cannot use -key and -key-file at the same time")
	}

	if *fSalt == "" && *fSaltFile == "" {
		return errors.New("no salt specified, use -salt or -salt-file to specify it")
	}
	if *fSalt != "" && *fSaltFile != "" {
		return errors.New("cannot use -salt and -salt-file at the same time")
	}

	var hashFunc func() hash.Hash
	switch *fHashFunc {
	case "SHA-1":
		hashFunc = sha1.New
	case "SHA-224":
		hashFunc = sha256.New224
	case "SHA-256":
		hashFunc = sha256.New
	case "SHA-384":
		hashFunc = sha512.New384
	case "SHA-512":
		hashFunc = sha512.New
	default:
		return errors.New("hash function is not valid")
	}

	var key []byte
	if *fKey != "" {
		b, err := hex.DecodeString(*fKey)
		if err != nil {
			return err
		}
		key = b
	}
	if *fKeyFile != "" {
		b, err := ioutil.ReadFile(*fKeyFile)
		if err != nil {
			return err
		}
		key = b
	}

	var salt []byte
	if *fSalt != "" {
		b, err := hex.DecodeString(*fSalt)
		if err != nil {
			return err
		}
		salt = b
	}
	if *fSaltFile != "" {
		b, err := ioutil.ReadFile(*fSaltFile)
		if err != nil {
			return err
		}
		salt = b
	}

	var w io.Writer
	if *fOutput == "" {
		w = os.Stdout
	} else {
		f, err := os.Create(*fOutput)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}

	output := pbkdf2.Key(key, salt, *fIter, *fLen, hashFunc)

	if _, err := io.Copy(w, bytes.NewBuffer(output)); err != nil {
		return err
	}

	return nil
}
