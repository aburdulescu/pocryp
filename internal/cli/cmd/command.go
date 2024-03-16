package cmd

import (
	"errors"
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

func (c *Command) Parse() (help bool, err error) {
	err = c.Flags.Parse(c.Args)
	return errors.Is(err, flag.ErrHelp), err
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
		nFlags := 0
		c.Flags.VisitAll(func(f *flag.Flag) { nFlags++ })

		fmt.Print(c.Usage)
		fmt.Println("")

		if nFlags != 0 {
			fmt.Println("Options:")
			c.Flags.PrintDefaults()
			fmt.Println("")
		}
	}
}
