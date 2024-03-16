package cmd

import (
	"testing"
)

func TestEncode(t *testing.T) {
	EncodeCmd.Args = []string{"-foo"}
	EncodeCmd.Init()
	if err := runEncode(EncodeCmd); err == nil {
		t.Fatal("expected error")
	}
}
