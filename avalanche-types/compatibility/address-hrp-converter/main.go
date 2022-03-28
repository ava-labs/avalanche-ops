package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/ava-labs/avalanchego/utils/constants"
	"github.com/ava-labs/avalanchego/utils/formatting"
)

// go run main.go avax18jma8ppw3nhx5r4ap8clazz0dps7rv5ukulre5 9999
// go run main.go avax1vkzy5p2qtumx9svjs9pvds48s0hcw80fkqcky9 9999
func main() {
	if len(os.Args) != 3 {
		panic(fmt.Errorf("expected 3 args, got %d", len(os.Args)))
	}

	networkID, err := strconv.ParseUint(os.Args[2], 10, 32)
	if err != nil {
		panic(err)
	}
	hrp := constants.GetHRP(uint32(networkID))

	addr := os.Args[1]
	_, b, err := formatting.ParseBech32(addr)
	if err != nil {
		panic(err)
	}
	convertedAddr, err := formatting.FormatBech32(hrp, b)
	if err != nil {
		panic(err)
	}
	fmt.Println(convertedAddr)
}
