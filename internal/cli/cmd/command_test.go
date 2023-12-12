package cmd

import (
	"testing"
)

func TestParse(t *testing.T) {
	c := Command{
		Run:   func(*Command) error { return nil },
		Name:  "foo",
		Usage: "bar",
		Brief: "baz",
	}

	c.Init()

	t.Run("Err", func(t *testing.T) {
		c.Args = []string{"-foo"}
		if err := c.Parse(); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("Ok", func(t *testing.T) {
		c.Args = []string{"foo", "bar"}
		if err := c.Parse(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestInit(t *testing.T) {
	tests := []struct {
		name string
		msg  string
		cmd  Command
	}{
		{
			name: "NoRun",
			msg:  "cmd: missing Run",
			cmd:  Command{},
		},

		{
			name: "NoName",
			msg:  "cmd: missing Name",
			cmd: Command{
				Run: func(*Command) error { return nil },
			},
		},

		{
			name: "NoUsage",
			msg:  "cmd: missing Usage",
			cmd: Command{
				Run:  func(*Command) error { return nil },
				Name: "foo",
			},
		},

		{
			name: "NoBrief",
			msg:  "cmd: missing Brief",
			cmd: Command{
				Run:   func(*Command) error { return nil },
				Name:  "foo",
				Usage: "bar",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			defer expectPanic(t, test.msg)
			test.cmd.Init()
		})
	}

	t.Run("Ok", func(t *testing.T) {
		c := Command{
			Run:   func(*Command) error { return nil },
			Name:  "foo",
			Usage: "bar",
			Brief: "baz",
		}
		c.Init()
		c.Flags.Usage()
	})
}

func expectPanic(t *testing.T, msg string) {
	t.Helper()
	r := recover()
	if r == nil {
		t.Fatal("expected panic")
	}
	if r != msg {
		t.Fatalf("want %q, have %q", msg, r)
	}
}
