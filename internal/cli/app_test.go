package cli

import (
	"testing"

	"bandr.me/p/pocryp/internal/cli/cmd"
)

func TestApp(t *testing.T) {
	var app App

	if err := app.Run(); err != nil {
		t.Fatal(err)
	}

	if err := app.Run("nothing"); err == nil {
		t.Fatal("expected an error")
	}

	app.Add("foo", &cmd.Command{
		Name:  "bar",
		Brief: "bar",
		Usage: "bar",
		Run:   func(*cmd.Command) error { return nil },
	})
	app.Add("foo", &cmd.Command{
		Name:  "baz",
		Brief: "baz",
		Usage: "baz",
		Run:   func(*cmd.Command) error { return nil },
	})
	app.Add("fizz", &cmd.Command{
		Name:  "buzz",
		Brief: "barr",
		Usage: "barr",
		Run:   func(*cmd.Command) error { return nil },
	})

	if err := app.Run("nothing"); err == nil {
		t.Fatal("expected an error")
	}

	if err := app.Run("bar"); err != nil {
		t.Fatal(err)
	}

	app.Usage()
}
