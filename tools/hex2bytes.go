package main

import (
	"log"
	"os"
)

func main() {
	args := os.Args[1:]

	for i, arg := range args {
		if len(arg)%2 != 0 {
			log.Fatalf("input #%d len not even", i)
		}

		print("[]byte{")
		for i := 0; i < len(arg); i += 2 {
			print("0x", arg[i:i+2], ",")
		}
		print("}\n")
	}
}
