# Key generation

- [x] AES
- [x] RSA

# Block ciphers

- [x] ECB
[test vectors](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)

# Stream ciphers

- [x] CBC
[test vectors](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)
- [ ] CTR
[test vectors](https://www.rfc-editor.org/rfc/rfc3686#section-6)
- [ ] ChaCha20
- [ ] Salsa20

# Key wrapping

- [x] KEYWRAP
[test vectors](https://www.rfc-editor.org/rfc/rfc3394#section-4)

# AEAD

- [x] GCM
[test vectors](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip)
- [ ] ChaCha20-Poly1305

# MAC

- [ ] CMAC
- [ ] GMAC
- [ ] HMAC
- [ ] Poly1305

# RSA

- [x] Public key from Private key
- [x] RSA-KEM
[RFC5990](https://www.rfc-editor.org/rfc/rfc5990)
- [x] raw <-> PKCS#1 ASN.1 DER
- [x] PEM <-> PKCS#1 ASN.1 DER

# HASH

- [x] SHA1
- [x] SHA256(224 and 256)
- [x] SHA512(384, 512, 512/224, and 512/256)
- [ ] SHA3
- [ ] BLAKE

# KDF

- [x] PBKDF2
- [ ] HKDF
- [ ] scrypt
- [ ] argon2

# EdDSA

- [ ] ED25519

# ECDH

- [ ] CURVE25519
