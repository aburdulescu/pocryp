package mup

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"

	"bandr.me/p/pocryp/internal/aes/cmac"
	"bandr.me/p/pocryp/internal/aes/mp"
	"bandr.me/p/pocryp/internal/she"
)

type Input struct {
	// SHE module Unique ID as hex string
	UID string

	// ID of the secret key
	AuthID she.KeyID

	// secret key as hex string
	AuthKey string

	// ID of the slot to be updated
	ID she.KeyID

	// the new value of the key as hex string
	NewKey string

	// new value of the counter
	Counter uint32

	// key flags
	Flags ProtectionFlags
}

var withLogs = false

// WithLogs will enable verbose logs for this package(useful for debugging)
func WithLogs() {
	withLogs = true
}

func Decode(m1m2m3, authKey []byte) (*Input, error) {
	if len(m1m2m3) < 64 {
		return nil, fmt.Errorf("invalid input length: %d", len(m1m2m3))
	}

	var in Input

	in.AuthKey = hex.EncodeToString(authKey)

	k1, k2, err := deriveKeys(authKey)
	if err != nil {
		return nil, err
	}

	if err := in.decodeM3(m1m2m3[:48], m1m2m3[48:64], k2); err != nil {
		return nil, err
	}

	if err := in.decodeM2(m1m2m3[16:48], k1); err != nil {
		return nil, err
	}

	if err := in.decodeM1(m1m2m3[:16]); err != nil {
		return nil, err
	}

	return &in, nil
}

func SliceMs(m1m2m3m4m5 [112]byte) (m1 []byte, m2 []byte, m3 []byte, m4 []byte, m5 []byte) {
	m1 = m1m2m3m4m5[:16]
	m2 = m1m2m3m4m5[16:48]
	m3 = m1m2m3m4m5[48:64]
	m4 = m1m2m3m4m5[64:96]
	m5 = m1m2m3m4m5[96:112]
	return
}

// Encode the memory update protocol data(M1, M2, M3, M4, M5).
func (in Input) Encode() (result [112]byte, err error) {
	if err := in.ID.IsCompatible(in.AuthID); err != nil {
		return result, err
	}

	authKey, err := decodeAesKey(in.AuthKey)
	if err != nil {
		return result, fmt.Errorf("AuthKey: %w", err)
	}

	newKey, err := decodeAesKey(in.NewKey)
	if err != nil {
		return result, fmt.Errorf("NewKey: %w", err)
	}

	k1, k2, err := deriveKeys(authKey)
	if err != nil {
		return result, err
	}

	k3, k4, err := deriveKeys(newKey)
	if err != nil {
		return result, err
	}

	if withLogs {
		log.Println("K1:", hex.EncodeToString(k1))
		log.Println("K2:", hex.EncodeToString(k2))
		log.Println("K3:", hex.EncodeToString(k3))
		log.Println("K4:", hex.EncodeToString(k4))
	}

	m1, err := in.encodeM1()
	if err != nil {
		return result, err
	}

	m2, err := in.encodeM2(newKey, k1)
	if err != nil {
		return result, err
	}

	m3, err := in.encodeM3(k2, m1, m2)
	if err != nil {
		return result, err
	}

	m4, err := in.encodeM4(k3, m1)
	if err != nil {
		return result, err
	}

	m5, err := in.encodeM5(k4, m4)
	if err != nil {
		return result, err
	}

	copy(result[0:16], m1)
	copy(result[16:48], m2)
	copy(result[48:64], m3)
	copy(result[64:96], m4)
	copy(result[96:112], m5)

	return result, nil
}

func decodeAesKey(hexKey string) ([]byte, error) {
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, err
	}
	if len(key) != 16 {
		return nil, fmt.Errorf("expected length is 16 bytes, have %d bytes", len(key))
	}
	return key, nil
}

func deriveKeys(key []byte) ([]byte, []byte, error) {
	encConst := sheKeyUpdateEncConstBase.encode()
	macConst := sheKeyUpdateMacConstBase.encode()

	if withLogs {
		log.Println("ENC_C:", hex.EncodeToString(encConst))
		log.Println("MAC_C:", hex.EncodeToString(macConst))
	}

	k1, err := mp.Compress(key, encConst)
	if err != nil {
		return nil, nil, err
	}

	k2, err := mp.Compress(key, macConst)
	if err != nil {
		return nil, nil, err
	}

	return k1, k2, nil
}

func (in Input) encodeM1() ([]byte, error) {
	uid, err := hex.DecodeString(in.UID)
	if err != nil {
		return nil, err
	}

	if len(uid) != 15 {
		return nil, fmt.Errorf("UID expected length is 15 bytes, have %d bytes", len(uid))
	}

	if withLogs {
		log.Println("UID:", in.UID)
		log.Println("ID:", in.ID)
		log.Println("AuthID:", in.AuthID)
	}

	var r []byte
	r = append(r, uid...)
	r = append(r, uint8(in.ID)<<4|uint8(in.AuthID))

	return r, nil
}

func (in *Input) decodeM1(m1 []byte) error {
	if len(m1) != 16 {
		return fmt.Errorf("invalid input length: %d", len(m1))
	}

	id := she.KeyID((m1[15] >> 4) & 0x0f)
	authId := she.KeyID(m1[15] & 0x0f)

	if !id.IsValid() {
		return fmt.Errorf("ID %s is not valid", id)
	}
	if !authId.IsValid() {
		return fmt.Errorf("ID %s is not valid", authId)
	}

	in.UID = hex.EncodeToString(m1[:15])
	in.AuthID = authId
	in.ID = id

	if withLogs {
		log.Println("UID:", in.UID)
		log.Println("ID:", in.ID)
		log.Println("AuthID:", in.AuthID)
	}

	return nil
}

func (in Input) encodeM2(newKey, k1 []byte) ([]byte, error) {
	flags := in.Flags.encode()

	if withLogs {
		log.Printf("CID: 0b%032b %v\n", in.Counter, in.Counter)
		log.Printf("FID: 0b%08b %v\n", flags, in.Flags)
	}

	counterAndFlags, err := encodeCounterAndFlags(in.Counter, flags)
	if err != nil {
		return nil, err
	}

	data := make([]byte, 32)

	copy(data[0:8], counterAndFlags[:])
	copy(data[16:], newKey)

	return cbcEncrypt(k1, m2IV[:], data)
}

var m2IV [16]byte // all zeros

func (in *Input) decodeM2(m2, k1 []byte) error {
	if len(m2) != 32 {
		return fmt.Errorf("invalid length for m2: %d", len(m2))
	}

	data, err := cbcDecrypt(k1, m2IV[:], m2)
	if err != nil {
		return err
	}

	counter, flags := decodeCounterAndFlags(data[0:5])

	in.Flags.decode(flags)

	in.Counter = counter
	in.NewKey = hex.EncodeToString(data[16:])

	return nil
}

func (in Input) encodeM3(k2, m1, m2 []byte) ([]byte, error) {
	var m1m2 []byte
	m1m2 = append(m1m2, m1...)
	m1m2 = append(m1m2, m2...)
	return cmac.Generate(k2, m1m2)
}

func (in *Input) decodeM3(m1m2, m3, k2 []byte) error {
	if len(m1m2) != 48 {
		return fmt.Errorf("invalid length for m1m2: %d", len(m1m2))
	}
	if len(m3) != 16 {
		return fmt.Errorf("invalid length for m3: %d", len(m3))
	}
	if !cmac.Verify(k2, m1m2, m3) {
		return fmt.Errorf("verification of M3 failed")
	}
	return nil
}

func (in Input) encodeM4(k3, m1 []byte) ([]byte, error) {
	counter, err := encodeCounterAndFlags(in.Counter, 0)
	if err != nil {
		return nil, err
	}

	// set bit 3 to 1
	counter[3] |= 0b00001000

	data := make([]byte, 32)

	copy(data[:16], m1)
	copy(data[16:], counter[:])

	ecb(k3, data[16:])

	return data, nil
}

func ecb(key, in []byte) {
	block, _ := aes.NewCipher(key)
	for len(in) > 0 {
		block.Encrypt(in, in)
		in = in[16:]
	}
}

func (in Input) encodeM5(k4, m4 []byte) ([]byte, error) {
	return cmac.Generate(k4, m4)
}

type keyUpdateConst [4]uint32

func (c keyUpdateConst) encode() []byte {
	r := make([]byte, 16)
	binary.BigEndian.PutUint32(r[0:4], c[0])
	binary.BigEndian.PutUint32(r[4:8], c[1])
	binary.BigEndian.PutUint32(r[8:12], c[2])
	binary.BigEndian.PutUint32(r[12:16], c[3])
	return r
}

var (
	sheKeyUpdateEncConstBase = keyUpdateConst{0x01015348, 0x45008000, 0x00000000, 0x000000b0}
	sheKeyUpdateMacConstBase = keyUpdateConst{0x01025348, 0x45008000, 0x00000000, 0x000000b0}
)

func cbcEncrypt(key, iv, plaintext []byte) ([]byte, error) {
	return cbc(key, iv, plaintext, true)
}

func cbcDecrypt(key, iv, plaintext []byte) ([]byte, error) {
	return cbc(key, iv, plaintext, false)
}

func cbc(key, iv, in []byte, direction bool) ([]byte, error) {
	if len(in)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("data is not a multiple of the block size")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(in))
	var mode cipher.BlockMode
	if direction {
		mode = cipher.NewCBCEncrypter(block, iv)
	} else {
		mode = cipher.NewCBCDecrypter(block, iv)
	}
	mode.CryptBlocks(out, in)
	return out, nil
}

type ProtectionFlags struct {
	// Enable write-protection
	Write bool
	// Enable boot-protection
	Boot bool
	// Enable debugger-protection
	Debugger bool
	// key usage: false=encryption/decryption, true=MAC generation/verification
	KeyUsage bool
	// Enable wildcard-protection
	Wildcard bool
}

func (f ProtectionFlags) String() string {
	return fmt.Sprintf(
		"WRITE_PROTECTION=%v, BOOT_PROTECTION=%v, DEBUGGER_PROTECTION=%v, KEY_USAGE=%v, WILDCARD=%v}",
		f.Write,
		f.Boot,
		f.Debugger,
		f.KeyUsage,
		f.Wildcard,
	)
}

func (f *ProtectionFlags) decode(v uint8) {
	f.Write = getBit(v, 4) == 1
	f.Boot = getBit(v, 3) == 1
	f.Debugger = getBit(v, 2) == 1
	f.KeyUsage = getBit(v, 1) == 1
	f.Wildcard = getBit(v, 0) == 1
}

func (f ProtectionFlags) encode() uint8 {
	var v uint8
	if f.Write {
		v |= 1 << 4
	}
	if f.Boot {
		v |= 1 << 3
	}
	if f.Debugger {
		v |= 1 << 2
	}
	if f.KeyUsage {
		v |= 1 << 1
	}
	if f.Wildcard {
		v |= 1
	}
	return v
}

// get bit value of bit number 'i' from 'v'
func getBit(v uint8, i int) uint8 {
	mask := uint8(1) << i
	byteVal := (v & mask) >> i
	bitVal := byteVal & 0x01
	return bitVal
}

const counterMax uint32 = 0x0fffffff

func encodeCounterAndFlags(counter uint32, flags uint8) (b [5]byte, err error) {
	if counter > counterMax {
		return b, fmt.Errorf("counter is too big, max value is 0x%08x(%d)", counterMax, counterMax)
	}

	// get rid of the 4 extra bits
	counter <<= 4

	b[0] = byte(counter >> 24)
	b[1] = byte(counter >> 16)
	b[2] = byte(counter >> 8)
	b[3] = byte(counter)

	b[3] |= (flags >> 1) & 0x0f
	b[4] = flags << 7

	return b, nil
}

func decodeCounterAndFlags(b []byte) (counter uint32, flags uint8) {
	counter = uint32(b[3]) | uint32(b[2])<<8 | uint32(b[1])<<16 | uint32(b[0])<<24
	counter >>= 4
	flags = (b[3] & 0xf << 1) | (b[4] >> 7)
	return counter, flags
}
