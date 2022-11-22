package main

import (
	"testing"
)

func TestApp(t *testing.T) {
	var app App

	if err := app.Run(nil); err != nil {
		t.Fatal(err)
	}

	if err := app.Run([]string{"nothing"}); err == nil {
		t.Fatal("expected an error")
	}

	app.Add("foo", Command{
		name:  "bar",
		usage: "bar",
		run:   func(args []string) error { return nil },
	})
	app.Add("foo", Command{
		name:  "baz",
		usage: "baz",
		run:   func(args []string) error { return nil },
	})
	app.Add("fizz", Command{
		name:  "buzz",
		usage: "barr",
		run:   func(args []string) error { return nil },
	})

	if err := app.Run([]string{"nothing"}); err == nil {
		t.Fatal("expected an error")
	}

	if err := app.Run([]string{"bar"}); err != nil {
		t.Fatal(err)
	}

	app.Usage()
}
