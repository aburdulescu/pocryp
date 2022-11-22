package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

type Command struct {
	name  string
	usage string
	run   func([]string) error
}

type Category struct {
	name     string
	commands []Command
}

type App struct {
	categories []Category
}

func (a App) Run(args []string) error {
	if len(args) == 0 {
		a.Usage()
		return nil
	}
	name := args[0]
	args = args[1:]
	for _, category := range a.categories {
		for _, cmd := range category.commands {
			if cmd.name == name {
				return cmd.run(args)
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
			if len(cmd.name) > max {
				max = len(cmd.name)
			}
		}
	}
	return max
}

func (a App) Usage() {
	w := os.Stderr
	fmt.Fprint(w, "Usage: pocryp command [ARGS]\n\nCommands:\n\n")
	for _, v := range a.categories {
		fmt.Fprintf(w, "%s:\n", v.name)
		mlen := a.maxCommandName(v.name)
		for _, cmd := range v.commands {
			padding := strings.Repeat(" ", mlen-len(cmd.name))
			fmt.Fprintf(w, "  %s%s  %s\n", cmd.name, padding, cmd.usage)
		}
		fmt.Fprint(w, "\n")
	}
	fmt.Fprint(w, "Run 'pocryp command -h' for more information about a command.\n")
}
