package util

import (
	"testing"

	"bandr.me/p/pocryp/internal/testutil"
)

func TestPrivateKeyFromPem(t *testing.T) {
	t.Run("InvalidInput", func(t *testing.T) {
		if _, err := PrivateKeyFromPem([]byte{1, 2}); err == nil {
			t.Fatal("expected err")
		}
	})
	t.Run("ValidInputWrongKey", func(t *testing.T) {
		in := testutil.ReadFile(t, "testdata/rsa2048_public_key.pem")
		_, err := PrivateKeyFromPem(in)
		if err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("ValidInputRightKey", func(t *testing.T) {
		in := testutil.ReadFile(t, "testdata/rsa2048_private_key.pem")
		key, err := PrivateKeyFromPem(in)
		if err != nil {
			t.Fatal(err)
		}
		if key == nil {
			t.Fatal("nil key")
		}
	})
}

func TestPublicKeyFromPem(t *testing.T) {
	t.Run("InvalidInput", func(t *testing.T) {
		if _, err := PublicKeyFromPem([]byte{1, 2}); err == nil {
			t.Fatal("expected err")
		}
	})
	t.Run("ValidInputWrongKey", func(t *testing.T) {
		in := testutil.ReadFile(t, "testdata/rsa2048_private_key.pem")
		_, err := PublicKeyFromPem(in)
		if err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("ValidInputRightKey", func(t *testing.T) {
		in := testutil.ReadFile(t, "testdata/rsa2048_public_key.pem")
		key, err := PublicKeyFromPem(in)
		if err != nil {
			t.Fatal(err)
		}
		if key == nil {
			t.Fatal("nil key")
		}
	})
}
