# pocryp
Command line utility for cryptographic primitives

## progress

### AES

- [x] Key gen
- [x] ECB
[test vectors](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)
- [x] CBC
[test vectors](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)
- [x] KEYWRAP
[test vectors](https://www.rfc-editor.org/rfc/rfc3394#section-4)
- [x] GCM
[test vectors](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip)
- [ ] CTR
[test vectors](https://www.rfc-editor.org/rfc/rfc3686#section-6)
- [ ] CMAC
- [ ] GMAC

### RSA

- [x] Key gen
- [x] RSA_KEM
- [x] raw <-> PKCS#1 ASN.1 DER
- [x] PEM <-> PKCS#1 ASN.1 DER

### SHA

tbd

### KDF

- [x] PBKDF2
