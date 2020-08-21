package jwkc

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/spf13/cobra"
	"gopkg.in/square/go-jose.v2"
	"io"
	"io/ioutil"
	"os"
)

func ConvertToJWKFormat(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		_ = cmd.Usage()
		return
	}

	var blocks []*pem.Block

	for _, arg := range args {
		stat, err := os.Stat(arg)
		if err != nil {
			fmt.Println(err.Error())
			return
		}
		if stat.IsDir() {
			fmt.Println("input is a directory")
			return
		}
		file, err := os.OpenFile(arg, os.O_RDONLY, 755)
		if err != nil {
			fmt.Println(err.Error())
			return
		}
		allBytes, err := ioutil.ReadAll(file)
		if err != nil {
			fmt.Println(err.Error())
			return
		}
		for len(allBytes) > 0 {
			var block *pem.Block
			block, allBytes = pem.Decode(allBytes)
			blocks = append(blocks, block)
		}
	}
	if len(blocks) > 0 {
		jwkSet := jose.JSONWebKeySet{}
		for _, block := range blocks {
			key, err := convertToKey(block)
			if err != nil {
				fmt.Println(err.Error())
			} else {
				jwKey := jose.JSONWebKey{
					Key:       key,
					KeyID:     block.Headers["kid"],
					Use:       block.Headers["use"],
					Algorithm: block.Headers["alg"],
				}
				jwkSet.Keys = append(jwkSet.Keys, jwKey)
			}
		}
		var output io.Writer
		outfile, _ := cmd.InheritedFlags().GetString("out")
		var err error
		if outfile != "" {
			var file *os.File
			file, err = os.OpenFile(outfile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
			if err != nil {
				fmt.Println(err.Error())
				return
			}
			output = file
			defer closeFile(file)
		} else {
			output = os.Stdout
		}
		data, err := json.Marshal(jwkSet)
		if err != nil {
			fmt.Println(err.Error())
		}
		_, err = output.Write(data)
		if err != nil {
			fmt.Println(err.Error())
		}
	} else {
		fmt.Println("no key found in inputs")
	}
}

func closeFile(file *os.File) {
	err := file.Sync()
	if err != nil {
		fmt.Println(err.Error())
	}
	err = file.Close()
	if err != nil {
		fmt.Println(err.Error())
	}
}

func convertToKey(block *pem.Block) (interface{}, error) {
	switch block.Type {
	case "RSA PUBLIC KEY":
		return x509.ParsePKCS1PublicKey(block.Bytes)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PUBLIC KEY":
		return x509.ParsePKIXPublicKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("key type %s is not recognized", block.Type)
	}
}
