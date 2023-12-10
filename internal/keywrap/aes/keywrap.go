package aes

import (
	"crypto/aes"
	"crypto/subtle"
	"encoding/binary"
	"errors"

	"bandr.me/p/pocryp/internal/util"
)

var aesKeyWrapDefaultIV = []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}

func Wrap(kek, plaintext []byte) ([]byte, error) {
	// RFC 3394 Key Wrap - 2.2.1 (index method)

	const blkSize = 8

	P := plaintext

	if len(P)%blkSize != 0 {
		return nil, errors.New("plaintext not 8 byte aligned")
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}

	n := len(P) / blkSize

	// 1) Initialize variables.
	var bufA [blkSize]byte
	A := bufA[:]
	copy(A, aesKeyWrapDefaultIV)

	R := make([][blkSize]byte, n)
	for i := range R {
		copy(R[i][:], P[i*blkSize:])
	}

	// AES block
	var bufB [16]byte
	B := bufB[:]

	//  2) Calculate intermediate values.
	for j := 0; j <= 5; j++ {
		for i := 1; i <= n; i++ {
			// B = A | R[i]
			if err := util.Concat(B, A, R[i-1][:]); err != nil {
				return nil, err
			}

			// B = AES(K, A | R[i])
			block.Encrypt(B, B)

			t := uint64((n * j) + i)
			msbB := binary.BigEndian.Uint64(B[:blkSize])

			// A = MSB(64, B) ^ t
			binary.BigEndian.PutUint64(A, msbB^t)

			lsbB := B[blkSize:]
			copy(R[i-1][:], lsbB)
		}
	}

	// 3) Output the results.

	// C = A + R
	C := make([]byte, (n+1)*blkSize)
	copy(C, A)
	for i := 0; i < n; i++ {
		copy(C[(i+1)*blkSize:], R[i][:])
	}

	return C, nil
}

func Unwrap(kek, ciphertext []byte) ([]byte, error) {
	// RFC 3394 Key Unwrap - 2.2.2 (index method)

	const blkSize = 8

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}

	C := ciphertext
	n := (len(C) / blkSize) - 1

	// 1) Initialize variables.
	var bufA [blkSize]byte
	A := bufA[:]
	copy(A, C[:blkSize])

	R := make([][blkSize]byte, n)
	for i := range R {
		copy(R[i][:], C[(i+1)*8:])
	}

	// AES block
	var bufB [16]byte
	B := bufB[:]

	var bufT [blkSize]byte
	T := bufT[:]

	// 2) Compute intermediate values.
	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			t := uint64((n * j) + i)
			binary.BigEndian.PutUint64(T, t)

			// B = AES-1(K, (A ^ t) | R[i])
			if err := util.Xor(B[:blkSize], A, T); err != nil {
				return nil, err
			}
			copy(B[blkSize:], R[i-1][:])
			block.Decrypt(B, B)

			// A = MSB(64, B)
			copy(A, B[:blkSize])

			// R[i] = LSB(64, B)
			copy(R[i-1][:], B[blkSize:])
		}
	}

	if subtle.ConstantTimeCompare(A, aesKeyWrapDefaultIV) != 1 {
		return nil, errors.New("integrity check failed - unexpected IV")
	}

	// 3) Output results.

	P := make([]byte, n*blkSize)
	for i := range R {
		copy(P[i*blkSize:], R[i][:])
	}

	return P, nil
}
