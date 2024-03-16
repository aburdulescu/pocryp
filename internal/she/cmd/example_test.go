package cmd

import (
	"testing"
)

func TestExample(t *testing.T) {
	ExampleCmd.Args = []string{"-foo"}
	ExampleCmd.Init()
	if err := runExample(ExampleCmd); err == nil {
		t.Fatal("expected error")
	}
}
