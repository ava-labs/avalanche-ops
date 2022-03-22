package main

import (
	"fmt"
	"os"

	"github.com/ava-labs/avalanchego/staking"
)

// go run ./cert-gen /tmp/test.insecure.key /tmp/test.insecure.crt
// go run main.go /tmp/test.insecure.key /tmp/test.insecure.crt
func main() {
	args := os.Args
	if len(args) < 3 {
		panic(fmt.Errorf("expected 3 args: main.go [KEY-PATH] [CERT-PATH], got %q", args))
	}

	stakingKeyPath, stakingCertPath := args[1], args[2]
	err := staking.InitNodeStakingKeyPair(stakingKeyPath, stakingCertPath)
	if err != nil {
		panic(err)
	}
}
