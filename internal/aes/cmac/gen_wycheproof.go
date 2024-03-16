//go:build ignore

// Download test vectors for AES-CMAC from wycheproof project
package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

func main() {
	if err := download(); err != nil {
		panic(err)
	}
}

var (
	jsonFile = "testdata/wycheproof/aes_cmac_test.json"
	url      = "https://raw.githubusercontent.com/google/wycheproof/master/testvectors_v1/aes_cmac_test.json"
)

func download() error {
	jsonFile = filepath.Clean(jsonFile)

	fmt.Println("download:", url)

	r, err := http.Get(url)
	if err != nil {
		return err
	}
	defer r.Body.Close()

	_ = os.MkdirAll(filepath.Dir(jsonFile), 0700)

	f, err := os.Create(jsonFile)
	if err != nil {
		return err
	}
	defer f.Close()

	fmt.Println("save:", jsonFile)

	_, err = io.Copy(f, r.Body)

	return err
}
