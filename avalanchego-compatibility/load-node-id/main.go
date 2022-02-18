package main

import (
	"fmt"
	"os"

	"github.com/ava-labs/avalanchego/ids"
	"github.com/ava-labs/avalanchego/staking"
	"github.com/ava-labs/avalanchego/utils/constants"
	"github.com/ava-labs/avalanchego/utils/hashing"
)

func main() {
	args := os.Args
	if len(args) < 3 {
		panic(fmt.Errorf("expected 2 args: main.go [KEY-PATH] [CERT-PATH], got %q", args))
	}

	// ref. config/config.go "getStakingTLSCertFromFile"
	stakingKeyPath, stakingCertPath := args[1], args[2]
	cert, err := staking.LoadTLSCertFromFiles(stakingKeyPath, stakingCertPath)
	if err != nil {
		panic(err)
	}

	// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/ids#ToShortID
	// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/ids#ShortID.PrefixedString
	nodeID, err := ids.ToShortID(hashing.PubkeyBytesToAddress(cert.Leaf.Raw))
	if err != nil {
		panic(err)
	}

	fmt.Println("Node ID:", nodeID.PrefixedString(constants.NodeIDPrefix))
}

// go run main.go ../../artifacts/staker1.insecure.key ../../artifacts/staker1.insecure.crt => NodeID-7Xhw2mDxuDS44j42TCB6U5579esbSt3Lg
// go run main.go ../../artifacts/staker2.insecure.key ../../artifacts/staker2.insecure.crt => NodeID-MFrZFVCXPv5iCn6M9K6XduxGTYp891xXZ
// go run main.go ../../artifacts/staker3.insecure.key ../../artifacts/staker3.insecure.crt => NodeID-NFBbbJ4qCmNaCzeW7sxErhvWqvEQMnYcN
// go run main.go ../../artifacts/staker4.insecure.key ../../artifacts/staker4.insecure.crt => NodeID-GWPcbFJZFfZreETSoWjPimr846mXEKCtu
// go run main.go ../../artifacts/staker5.insecure.key ../../artifacts/staker5.insecure.crt => NodeID-P7oB2McjBGgW2NXXWVYjV8JEDFoW9xDE5
// go run main.go ../../artifacts/test.insecure.key ../../artifacts/test.insecure.crt => NodeID-29HTAG5cfN2fw79A67Jd5zY9drcT51EBG
