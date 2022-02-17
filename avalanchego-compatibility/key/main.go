package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/ava-labs/avalanchego/utils/constants"
	"github.com/ava-labs/avalanchego/utils/crypto"
	"github.com/ava-labs/avalanchego/utils/formatting"
)

var keyFactory = new(crypto.FactorySECP256K1R)

// e.g., go run main.go PrivateKey-ewoqjP7PxY4yr3iLTpLisriqt94hdyDFNgchSxGGztUrTXtNN
func main() {
	privateKeyEncoded := ""
	args := os.Args
	if len(args) >= 2 {
		privateKeyEncoded = args[1]
	}

	var pk *crypto.PrivateKeySECP256K1R
	if privateKeyEncoded == "" {
		rpk, err := keyFactory.NewPrivateKey()
		if err != nil {
			panic(err)
		}
		pk, _ = rpk.(*crypto.PrivateKeySECP256K1R)
	} else {
		pkDecoded, err := decodePrivateKey(privateKeyEncoded)
		if err != nil {
			panic(err)
		}
		pk = pkDecoded
	}

	pkEncoded, err := encodePrivateKey(pk)
	if err != nil {
		panic(err)
	}
	fmt.Println("pkEncoded:", pkEncoded)

	pkDecoded, err := decodePrivateKey(pkEncoded)
	if err != nil {
		panic(err)
	}

	if !bytes.Equal(pk.Bytes(), pkDecoded.Bytes()) {
		panic(fmt.Errorf("pk.Bytes %s != pkDecoded.Bytes %s", pk.Bytes(), pkDecoded.Bytes()))
	}

	xMainAddr, err := encodeAddr(pk, "X", constants.GetHRP(1))
	if err != nil {
		panic(err)
	}
	pMainAddr, err := encodeAddr(pk, "P", constants.GetHRP(1))
	if err != nil {
		panic(err)
	}
	cMainAddr, err := encodeAddr(pk, "C", constants.GetHRP(1))
	if err != nil {
		panic(err)
	}
	shortAddr := encodeShortAddr(pk)

	fmt.Println("xMainAddr:", xMainAddr)
	fmt.Println("pMainAddr:", pMainAddr)
	fmt.Println("cMainAddr:", cMainAddr)
	fmt.Println("shortAddr:", shortAddr)
}

const (
	privKeyEncPfx = "PrivateKey-"
	privKeySize   = 64

	rawEwoqPk      = "ewoqjP7PxY4yr3iLTpLisriqt94hdyDFNgchSxGGztUrTXtNN"
	EwoqPrivateKey = "PrivateKey-" + rawEwoqPk
)

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

func encodeAddr(pk *crypto.PrivateKeySECP256K1R, chainIDAlias string, hrp string) (string, error) {
	pubBytes := pk.PublicKey().Address().Bytes()
	return formatting.FormatAddress(chainIDAlias, hrp, pubBytes)
}

func encodeShortAddr(pk *crypto.PrivateKeySECP256K1R) string {
	pubAddr := pk.PublicKey().Address()
	return pubAddr.String()
}
