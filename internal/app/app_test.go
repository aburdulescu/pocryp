package app

import (
	"testing"
)

func TestApp(t *testing.T) {
	var app App

	if err := app.Run(); err != nil {
		t.Fatal(err)
	}

	if err := app.Run("nothing"); err == nil {
		t.Fatal("expected an error")
	}

	app.Add("foo", Command{
		Name:  "bar",
		Usage: "bar",
		Run:   func(args ...string) error { return nil },
	})
	app.Add("foo", Command{
		Name:  "baz",
		Usage: "baz",
		Run:   func(args ...string) error { return nil },
	})
	app.Add("fizz", Command{
		Name:  "buzz",
		Usage: "barr",
		Run:   func(args ...string) error { return nil },
	})

	if err := app.Run("nothing"); err == nil {
		t.Fatal("expected an error")
	}

	if err := app.Run("foo-bar"); err != nil {
		t.Fatal(err)
	}

	app.Usage()
}
