package cmd

import (
	"flag"
	"fmt"
	"os"
)

type Cmd struct {
	// command name
	Name string

	// short usage message to be used in the app
	Short string

	// long usage message
	Long string

	// flag set
	Flags *flag.FlagSet
}

func (c *Cmd) Init() {
	if c.Name == "" {
		panic("cmd: missing Name")
	}
	c.Flags = flag.NewFlagSet(c.Name, flag.ContinueOnError)
	c.Flags.Usage = func() {
		fmt.Fprint(os.Stderr, c.Long)
		c.Flags.PrintDefaults()
	}
}
