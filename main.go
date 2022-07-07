package main

import (
	"go-seek/pkg/seek"
	"os"
)

func main() {
	strings := os.Args
	args := strings[1]
	print(args)
	seek.StartSeek(args)
	for true {

	}
}
