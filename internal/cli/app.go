package cli

import (
	"flag"
	"fmt"
	"os"
	"runtime/debug"
	"strings"

	"bandr.me/p/pocryp/internal/cli/cmd"
)

type App struct {
	categories []category

	printVersion bool
}

type category struct {
	name     string
	commands []*cmd.Command
}

func printAppVersion() {
	bi, _ := debug.ReadBuildInfo()
	valOf := func(k string) string {
		for _, v := range bi.Settings {
			if v.Key == k {
				return v.Value
			}
		}
		return ""
	}
	fmt.Println(
		bi.Main.Version,
		bi.GoVersion,
		valOf("GOOS"),
		valOf("GOARCH"),
		valOf("vcs.revision"),
		valOf("vcs.time"),
	)
}

func (a *App) Run(args ...string) error {
	fset := flag.NewFlagSet("pocryp", flag.ExitOnError)
	fset.SetOutput(os.Stdout)
	fset.Usage = a.Usage
	fset.BoolVar(&a.printVersion, "version", false, "")
	if err := fset.Parse(args); err != nil {
		return err
	}

	args = fset.Args()

	if a.printVersion {
		printAppVersion()
		return nil
	}

	if len(args) == 0 {
		a.Usage()
		return nil
	}

	name := args[0]
	args = args[1:]

	for _, category := range a.categories {
		for _, cmd := range category.commands {
			if cmd.Name == name {
				cmd.Args = args
				return cmd.Run(cmd)
			}
		}
	}

	return fmt.Errorf("unknown command '%s'", name)
}

func (a *App) Add(categoryName string, cmds ...*cmd.Command) {
	i := -1
	for ii, v := range a.categories {
		if v.name == categoryName {
			i = ii
		}
	}
	if i == -1 {
		a.categories = append(a.categories, category{name: categoryName})
		i = len(a.categories) - 1
	}
	cat := &a.categories[i]
	for _, cmd := range cmds {
		if err := cat.hasCmd(cmd.Name); err != nil {
			panic(err.Error())
		}
		cmd.Init()
	}
	cat.commands = append(cat.commands, cmds...)
}

func (c category) hasCmd(name string) error {
	for _, cmd := range c.commands {
		if cmd.Name == name {
			return fmt.Errorf("category '%s' already has a command name '%s'", c.name, name)
		}
	}
	return nil
}

func (a App) maxCommandName(category string) int {
	max := 0
	for _, v := range a.categories {
		if v.name != category {
			continue
		}
		for _, cmd := range v.commands {
			if len(cmd.Name) > max {
				max = len(cmd.Name)
			}
		}
	}
	return max
}

func (a App) Usage() {
	fmt.Print(`Usage: pocryp command [ARGS]

Flags:
  -h, --help  Print this message
  --version   Print version information

Commands(by category):

`)
	for _, v := range a.categories {
		fmt.Printf("%s:\n", v.name)
		mlen := a.maxCommandName(v.name)
		for _, cmd := range v.commands {
			padding := strings.Repeat(" ", mlen-len(cmd.Name))
			fmt.Printf("  %s%s  %s\n", cmd.Name, padding, cmd.Brief)
		}
		fmt.Print("\n")
	}
	fmt.Print("Run 'pocryp command -h' for more information about a command.\n")
}
