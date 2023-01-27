package app

import (
	"flag"
	"fmt"
	"os"
	"runtime/debug"
	"sort"
	"strings"
)

type Command struct {
	Run   func([]string) error
	Name  string
	Usage string
}

type Category struct {
	name     string
	commands []Command
}

type App struct {
	categories []Category

	printVersion bool
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

func (a *App) Run(args []string) error {
	fset := flag.NewFlagSet("pocryp", flag.ExitOnError)
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

	switch {
	case name == "version":
		printAppVersion()
		return nil
	case name == "help":
		a.Usage()
		return nil
	}

	for _, category := range a.categories {
		for _, cmd := range category.commands {
			if cmd.Name == name {
				return cmd.Run(args)
			}
		}
	}

	return fmt.Errorf("unknown command '%s'", name)
}

func (a *App) Add(category string, c Command) {
	i := -1
	for ii, v := range a.categories {
		if v.name == category {
			i = ii
		}
	}
	if i == -1 {
		a.categories = append(a.categories, Category{name: category})
		i = len(a.categories) - 1
	}
	a.categories[i].commands = append(a.categories[i].commands, c)
	sort.Slice(a.categories, func(i, j int) bool {
		return a.categories[i].name < a.categories[j].name
	})
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
	w := os.Stderr
	fmt.Fprint(w, `Usage: pocryp command [ARGS]

Flags:
  -h,--help  Print this message
  --version  Print version information

Commands:
  help     Print this message
  version  Print version information

`)
	for _, v := range a.categories {
		fmt.Fprintf(w, "%s:\n", v.name)
		mlen := a.maxCommandName(v.name)
		for _, cmd := range v.commands {
			padding := strings.Repeat(" ", mlen-len(cmd.Name))
			fmt.Fprintf(w, "  %s%s  %s\n", cmd.Name, padding, cmd.Usage)
		}
		fmt.Fprint(w, "\n")
	}
	fmt.Fprint(w, "Run 'pocryp command -h' for more information about a command.\n")
}
