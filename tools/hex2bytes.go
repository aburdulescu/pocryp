package main

import (
	"encoding/hex"
	"fmt"
	"os"
)

func main() {
	for _, arg := range os.Args[1:] {
		b, err := hex.DecodeString(arg)
		if err != nil {
			panic(err)
		}
		for _, v := range b {
			fmt.Printf("0x%02x,", v)
		}
		print("\n")
	}
}
