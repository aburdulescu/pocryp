package cmd

import (
	"flag"
	"fmt"
	"os"
)

type Command struct {
	Run   func(*Command) error
	Name  string
	Brief string
	Usage string

	Args  []string
	Flags *flag.FlagSet
}

func (c *Command) Parse() error {
	return c.Flags.Parse(c.Args)
}

func (c *Command) Init() {
	if c.Run == nil {
		panic("cmd: missing Run")
	}
	if c.Name == "" {
		panic("cmd: missing Name")
	}
	if c.Usage == "" {
		panic("cmd: missing Usage")
	}
	if c.Brief == "" {
		panic("cmd: missing Brief")
	}
	c.Flags = flag.NewFlagSet(c.Name, flag.ContinueOnError)
	c.Flags.SetOutput(os.Stdout)
	c.Flags.Usage = func() {
		fmt.Print(c.Usage)
		fmt.Println("Options:")
		c.Flags.PrintDefaults()
		fmt.Print("\n")
	}
}
