package mup

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"bandr.me/p/pocryp/internal/she"
)

func TestEncode(t *testing.T) {
	WithLogs()

	in := Input{
		UID:     "000000000000000000000000000001",
		AuthID:  she.MASTER_ECU_KEY,
		ID:      she.KEY_1,
		AuthKey: "000102030405060708090a0b0c0d0e0f",
		NewKey:  "0f0e0d0c0b0a09080706050403020100",
		Counter: 1,
		Flags: ProtectionFlags{
			KeyUsage: false,
		},
	}

	result, err := in.Encode()
	if err != nil {
		t.Fatal(err)
	}

	m1, m2, m3, m4, m5 := SliceMs(result)

	expectedM1, _ := hex.DecodeString("00000000000000000000000000000141")
	if !bytes.Equal(m1, expectedM1) {
		t.Log("want", hex.EncodeToString(expectedM1))
		t.Log("have", hex.EncodeToString(m1))
		t.Fatal("m1")
	}

	expectedM2, _ := hex.DecodeString("2b111e2d93f486566bcbba1d7f7a9797c94643b050fc5d4d7de14cff682203c3")
	if !bytes.Equal(m2, expectedM2) {
		t.Log("want", hex.EncodeToString(expectedM2))
		t.Log("have", hex.EncodeToString(m2))
		t.Fatal("m2")
	}

	expectedM3, _ := hex.DecodeString("b9d745e5ace7d41860bc63c2b9f5bb46")
	if !bytes.Equal(m3, expectedM3) {
		t.Log("want", hex.EncodeToString(expectedM3))
		t.Log("have", hex.EncodeToString(m3))
		t.Fatal("m3")
	}

	expectedM4, _ := hex.DecodeString("00000000000000000000000000000141b472e8d8727d70d57295e74849a27917")
	if !bytes.Equal(m4, expectedM4) {
		t.Log("want", hex.EncodeToString(expectedM4))
		t.Log("have", hex.EncodeToString(m4))
		t.Fatal("m4")
	}

	expectedM5, _ := hex.DecodeString("820d8d95dc11b4668878160cb2a4e23e")
	if !bytes.Equal(m5, expectedM5) {
		t.Log("want", hex.EncodeToString(expectedM5))
		t.Log("have", hex.EncodeToString(m5))
		t.Fatal("m5")
	}
}

func TestDecode(t *testing.T) {
	m1m2m3, _ := hex.DecodeString(
		"00000000000000000000000000000141" +
			"2b111e2d93f486566bcbba1d7f7a9797c94643b050fc5d4d7de14cff682203c3" +
			"b9d745e5ace7d41860bc63c2b9f5bb46",
	)

	authKey, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")

	in, err := Decode(m1m2m3, authKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(in)

	expectedIn := Input{
		UID:     "000000000000000000000000000001",
		AuthID:  she.MASTER_ECU_KEY,
		ID:      she.KEY_1,
		AuthKey: "000102030405060708090a0b0c0d0e0f",
		NewKey:  "0f0e0d0c0b0a09080706050403020100",
		Counter: 1,
		Flags: ProtectionFlags{
			KeyUsage: false,
		},
	}

	if err := in.equals(expectedIn); err != nil {
		t.Fatal(err)
	}
}

func TestCounterAndFlags(t *testing.T) {
	t.Run("CounterOverMax", func(t *testing.T) {
		_, err := encodeCounterAndFlags(counterMax+1, 0)
		if err == nil {
			t.Fatalf("expected error")
		}
	})

	t.Run("Ok", func(t *testing.T) {
		tests := []struct {
			name    string
			counter uint32
			flags   uint8
			b       []byte
		}{
			{
				name:    "All1",
				counter: 0x0fffffff,
				flags:   0x1f,
				b:       []byte{0xff, 0xff, 0xff, 0xff, 0x80},
			},
			{
				name:    "All0",
				counter: 0,
				flags:   0,
				b:       []byte{0, 0, 0, 0, 0},
			},
		}

		for _, test := range tests {

			t.Run(test.name, func(t *testing.T) {

				b, err := encodeCounterAndFlags(test.counter, test.flags)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(b[:], test.b) {
					t.Log("want:", hex.EncodeToString(test.b))
					t.Log("have:", hex.EncodeToString(b[:]))
					t.Fatal("fail")
				}

				decodedCounter, decodedFlags := decodeCounterAndFlags(b[:])
				if decodedCounter != test.counter {
					t.Fatalf("want 0x%08x, have 0x%08x", test.counter, decodedCounter)
				}
				if decodedFlags != test.flags {
					t.Fatalf("want 0x%08b, have 0x%08b", test.flags, decodedFlags)
				}
			})

		}

	})
}

func (in Input) equals(other Input) error {
	if in.UID != other.UID {
		return fmt.Errorf("UID: %q != %q", in.UID, other.UID)
	}
	if in.AuthID != other.AuthID {
		return fmt.Errorf("AuthID: %q != %q", in.AuthID, other.AuthID)
	}
	if in.ID != other.ID {
		return fmt.Errorf("ID: %q != %q", in.ID, other.ID)
	}
	if in.AuthKey != other.AuthKey {
		return fmt.Errorf("AuthKey: %q != %q", in.AuthKey, other.AuthKey)
	}
	if in.NewKey != other.NewKey {
		return fmt.Errorf("NewKey: %q != %q", in.NewKey, other.NewKey)
	}
	if in.Counter != other.Counter {
		return fmt.Errorf("Counter: %d != %d", in.Counter, other.Counter)
	}
	if err := in.Flags.equals(other.Flags); err != nil {
		return fmt.Errorf("Flags: %w", err)
	}
	return nil
}

func (f ProtectionFlags) equals(other ProtectionFlags) error {
	if f.Write != other.Write {
		return fmt.Errorf("Write: %v != %v", f.Write, other.Write)
	}
	if f.Boot != other.Boot {
		return fmt.Errorf("Boot: %v != %v", f.Boot, other.Boot)
	}
	if f.Debugger != other.Debugger {
		return fmt.Errorf("Debugger: %v != %v", f.Debugger, other.Debugger)
	}
	if f.KeyUsage != other.KeyUsage {
		return fmt.Errorf("KeyUsage: %v != %v", f.KeyUsage, other.KeyUsage)
	}
	if f.Wildcard != other.Wildcard {
		return fmt.Errorf("Wildcard: %v != %v", f.Wildcard, other.Wildcard)
	}
	return nil
}
