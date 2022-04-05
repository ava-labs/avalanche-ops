package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/ava-labs/avalanchego/utils/constants"
	"github.com/ava-labs/avalanchego/utils/crypto"
	"github.com/ava-labs/avalanchego/utils/formatting"
	eth_crypto "github.com/ethereum/go-ethereum/crypto"
)

var keyFactory = new(crypto.FactorySECP256K1R)

// go run main.go ../../artifacts/test.insecure.secp256k1.key.infos.json
func main() {
	b, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}

	log.Print("loading key")
	var keyInfos []keyInfo
	if err := json.Unmarshal(b, &keyInfos); err != nil {
		panic(err)
	}

	for i, ki := range keyInfos {
		fmt.Printf("checking the key info at %d\n", i)
		k, err := decodePrivateKey(ki.PrivateKey)
		if err != nil {
			panic(err)
		}

		hex := hex.EncodeToString(k.Bytes())
		if hex != ki.PrivateKeyHex {
			panic(fmt.Errorf("unexpected PrivateKeyHex %q, expected %q", hex, ki.PrivateKeyHex))
		}

		xAddr, err := encodeAddr(k, "X", constants.GetHRP(1))
		if err != nil {
			panic(err)
		}
		if xAddr != ki.Addresses["1"].XAddress {
			panic(fmt.Errorf("unexpected xAddr %q, expected %q", xAddr, ki.Addresses["1"].XAddress))
		}
		pAddr, err := encodeAddr(k, "P", constants.GetHRP(1))
		if err != nil {
			panic(err)
		}
		if pAddr != ki.Addresses["1"].PAddress {
			panic(fmt.Errorf("unexpected pAddr %q, expected %q", pAddr, ki.Addresses["1"].PAddress))
		}
		cAddr, err := encodeAddr(k, "C", constants.GetHRP(1))
		if err != nil {
			panic(err)
		}
		if cAddr != ki.Addresses["1"].CAddress {
			panic(fmt.Errorf("unexpected cAddr %q, expected %q", cAddr, ki.Addresses["1"].CAddress))
		}

		xAddr, err = encodeAddr(k, "X", constants.GetHRP(9999))
		if err != nil {
			panic(err)
		}
		if xAddr != ki.Addresses["9999"].XAddress {
			panic(fmt.Errorf("unexpected xAddr %q, expected %q", xAddr, ki.Addresses["9999"].XAddress))
		}
		pAddr, err = encodeAddr(k, "P", constants.GetHRP(9999))
		if err != nil {
			panic(err)
		}
		if pAddr != ki.Addresses["9999"].PAddress {
			panic(fmt.Errorf("unexpected pAddr %q, expected %q", pAddr, ki.Addresses["9999"].PAddress))
		}
		cAddr, err = encodeAddr(k, "C", constants.GetHRP(9999))
		if err != nil {
			panic(err)
		}
		if cAddr != ki.Addresses["9999"].CAddress {
			panic(fmt.Errorf("unexpected cAddr %q, expected %q", cAddr, ki.Addresses["9999"].CAddress))
		}

		shortAddr1 := encodeShortAddr1(k)
		shortAddr2 := encodeShortAddr2(k)
		if shortAddr1 != shortAddr2 {
			panic(fmt.Errorf("unexpected different short address %q, %q", shortAddr1, shortAddr2))
		}
		if shortAddr1 != ki.ShortAddress {
			panic(fmt.Errorf("unexpected different short address %q, expected %q", shortAddr1, ki.ShortAddress))
		}

		ethAddr := encodeEthAddr(k)
		if ethAddr != ki.EthAddress {
			panic(fmt.Errorf("unexpected EthAddress %q, expected %q", ethAddr, ki.EthAddress))
		}
	}

	fmt.Println("SUCCESS")
}

type keyInfo struct {
	PrivateKey string `json:"private_key"`
	// ref. https://github.com/ava-labs/subnet-cli/blob/5b69345a3fba534fb6969002f41c8d3e69026fed/internal/key/key.go#L238-L258
	PrivateKeyHex string               `json:"private_key_hex"`
	Addresses     map[string]addresses `json:"addresses"`
	ShortAddress  string               `json:"short_address"`
	EthAddress    string               `json:"eth_address"`
}

type addresses struct {
	XAddress string `json:"x_address"`
	PAddress string `json:"p_address"`
	CAddress string `json:"c_address"`
}

const privKeyEncPfx = "PrivateKey-"

func decodePrivateKey(enc string) (*crypto.PrivateKeySECP256K1R, error) {
	rawPk := strings.Replace(enc, privKeyEncPfx, "", 1)
	skBytes, err := formatting.Decode(formatting.CB58, rawPk)
	if err != nil {
		return nil, err
	}
	rpk, err := keyFactory.ToPrivateKey(skBytes)
	if err != nil {
		return nil, err
	}
	privKey, ok := rpk.(*crypto.PrivateKeySECP256K1R)
	if !ok {
		return nil, fmt.Errorf("invalid type %T", rpk)
	}
	return privKey, nil
}

func encodeAddr(pk *crypto.PrivateKeySECP256K1R, chainIDAlias string, hrp string) (string, error) {
	pubBytes := pk.PublicKey().Address().Bytes()
	return formatting.FormatAddress(chainIDAlias, hrp, pubBytes)
}

func encodeShortAddr1(pk *crypto.PrivateKeySECP256K1R) string {
	pubBytes := pk.PublicKey().Address().Bytes()
	str, _ := formatting.EncodeWithChecksum(formatting.CB58, pubBytes)
	return str
}

func encodeShortAddr2(pk *crypto.PrivateKeySECP256K1R) string {
	pubAddr := pk.PublicKey().Address()
	return pubAddr.String()
}

func encodeEthAddr(pk *crypto.PrivateKeySECP256K1R) string {
	ethAddr := eth_crypto.PubkeyToAddress(pk.ToECDSA().PublicKey)
	return ethAddr.String()
}
