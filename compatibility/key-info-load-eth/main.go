package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/ava-labs/avalanchego/utils/constants"
	"github.com/ava-labs/avalanchego/utils/crypto"
	"github.com/ava-labs/avalanchego/utils/formatting"
	eth_crypto "github.com/ethereum/go-ethereum/crypto"
	"sigs.k8s.io/yaml"
)

var keyFactory = new(crypto.FactorySECP256K1R)

// go run main.go 56289e99c94b6912bfc12adc093c9b51124f0dc54ac7a766b2bc5ccf558d8027 1
// go run main.go 56289e99c94b6912bfc12adc093c9b51124f0dc54ac7a766b2bc5ccf558d8027 9999
// go run main.go e73b5812225f2e1c62de93fb6ec35a9338882991577f9a6d5651dce61cecd852 1
// go run main.go e73b5812225f2e1c62de93fb6ec35a9338882991577f9a6d5651dce61cecd852 9999
func main() {
	if len(os.Args) != 3 {
		panic(fmt.Errorf("expected 3 args, got %d", len(os.Args)))
	}

	networkID, err := strconv.ParseUint(os.Args[2], 10, 32)
	if err != nil {
		panic(err)
	}

	privKey := os.Args[1]
	privKeyRaw, err := hex.DecodeString(privKey)
	if err != nil {
		panic(err)
	}
	encodedPrivKey, err := formatting.EncodeWithChecksum(formatting.CB58, privKeyRaw)
	if err != nil {
		panic(err)
	}

	pk, err := decodePrivateKey(encodedPrivKey)
	if err != nil {
		panic(err)
	}

	pkEncoded, err := encodePrivateKey(pk)
	if err != nil {
		panic(err)
	}
	pkDecoded, err := decodePrivateKey(pkEncoded)
	if err != nil {
		panic(err)
	}
	if !bytes.Equal(pk.Bytes(), pkDecoded.Bytes()) {
		panic(fmt.Errorf("pk.Bytes %s != pkDecoded.Bytes %s", pk.Bytes(), pkDecoded.Bytes()))
	}

	xMainAddr, err := encodeAddr(pk, "X", constants.GetHRP(uint32(networkID)))
	if err != nil {
		panic(err)
	}
	pMainAddr, err := encodeAddr(pk, "P", constants.GetHRP(uint32(networkID)))
	if err != nil {
		panic(err)
	}
	cMainAddr, err := encodeAddr(pk, "C", constants.GetHRP(uint32(networkID)))
	if err != nil {
		panic(err)
	}
	shortAddr := encodeShortAddr1(pk)
	if addr2 := encodeShortAddr2(pk); shortAddr != addr2 {
		panic(fmt.Errorf("short address %s != %s", shortAddr, addr2))
	}

	ki := keyInfo{
		PrivateKey:    pkEncoded,
		PrivateKeyHex: hex.EncodeToString(pk.Bytes()),
		XAddress:      xMainAddr,
		PAddress:      pMainAddr,
		CAddress:      cMainAddr,
		ShortAddress:  shortAddr,
		EthAddress:    encodeEthAddr(pk),
	}
	b, err := yaml.Marshal(ki)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(b))
}

type keyInfo struct {
	PrivateKey string `json:"private_key"`
	// ref. https://github.com/ava-labs/subnet-cli/blob/5b69345a3fba534fb6969002f41c8d3e69026fed/internal/key/key.go#L238-L258
	PrivateKeyHex string `json:"private_key_hex"`
	XAddress      string `json:"x_address"`
	PAddress      string `json:"p_address"`
	CAddress      string `json:"c_address"`
	ShortAddress  string `json:"short_address"`
	EthAddress    string `json:"eth_address"`
}

const privKeyEncPfx = "PrivateKey-"

func encodePrivateKey(pk *crypto.PrivateKeySECP256K1R) (string, error) {
	privKeyRaw := pk.Bytes()
	enc, err := formatting.EncodeWithChecksum(formatting.CB58, privKeyRaw)
	if err != nil {
		return "", err
	}
	return privKeyEncPfx + enc, nil
}

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

func encodeShortAddr1(pk *crypto.PrivateKeySECP256K1R) string {
	pubBytes := pk.PublicKey().Address().Bytes()
	str, _ := formatting.EncodeWithChecksum(formatting.CB58, pubBytes)
	return str
}

func encodeShortAddr2(pk *crypto.PrivateKeySECP256K1R) string {
	pubAddr := pk.PublicKey().Address()
	return pubAddr.String()
}

func encodeAddr(pk *crypto.PrivateKeySECP256K1R, chainIDAlias string, hrp string) (string, error) {
	pubBytes := pk.PublicKey().Address().Bytes()
	return formatting.FormatAddress(chainIDAlias, hrp, pubBytes)
}

func encodeEthAddr(pk *crypto.PrivateKeySECP256K1R) string {
	ethAddr := eth_crypto.PubkeyToAddress(pk.ToECDSA().PublicKey)
	return ethAddr.String()
}
