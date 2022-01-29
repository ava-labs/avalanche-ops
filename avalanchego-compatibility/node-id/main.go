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

	// "go run main.go ../../artifacts/staker1.key ../../artifacts/staker1.crt"
	// should return "NodeID-7Xhw2mDxuDS44j42TCB6U5579esbSt3Lg"
	// ref. https://docs.avax.network/build/tutorials/platform/create-a-local-test-network/#manually
	fmt.Println(nodeID.PrefixedString(constants.NodeIDPrefix))
}
