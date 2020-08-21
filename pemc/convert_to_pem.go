package pemc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/spf13/cobra"
	"gopkg.in/square/go-jose.v2"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
)

var (
	OutputFile string
	IgnoreSSL  bool
)

func ConvertToPEMFormat(cmd *cobra.Command, args []string) {
	var keys *jose.JSONWebKeySet
	var err error
	if len(args) < 1 {
		_ = cmd.Usage()
		return
	}
	input := args[0]
	if strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://") ||
		strings.HasPrefix(input, "HTTP://") || strings.HasPrefix(input, "HTTPS://") {
		IgnoreSSL, _ = cmd.Flags().GetBool("no-verify")
		keys, err = LoadJSONWebKeySetFromURL(input)
	} else {
		keys, err = LoadJSONWebKeySetFromFile(input)
	}
	OutputFile, _ = cmd.InheritedFlags().GetString("out")
	if err != nil {
		fmt.Println(err.Error())
	} else {
		for i, key := range keys.Keys {
			pemBlock, err := ConvertToPEMBlock(key.Key)
			if err != nil {
				fmt.Println(err.Error())
			} else {
				pemBlock.Headers = make(map[string]string, 0)
				pemBlock.Headers["kid"] = key.KeyID
				pemBlock.Headers["alg"] = key.Algorithm
				pemBlock.Headers["use"] = key.Use
				thumbprint, err := key.Thumbprint(crypto.SHA1)
				if err != nil {
					fmt.Printf(err.Error())
				}
				fmt.Printf("kid: %s >>> sha1: %s", key.KeyID, hex.EncodeToString(thumbprint))
				var output io.Writer
				if OutputFile != "" {
					if len(keys.Keys) == 1 {
						output, err = os.OpenFile(OutputFile, os.O_CREATE|os.O_RDWR, 0644)
					} else {
						output, err = os.OpenFile(OutputFile+"_"+strconv.Itoa(i), os.O_CREATE|os.O_RDWR, 0644)
					}
				} else {
					output = os.Stdout
				}
				if err != nil {
					fmt.Println(err.Error())
				} else {
					if err = pem.Encode(output, pemBlock); err != nil {
						fmt.Println(err.Error())
					}
				}
			}
		}
	}
}

func LoadJSONWebKeySetFromFile(file string) (*jose.JSONWebKeySet, error) {
	fileReader, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	keySet := jose.JSONWebKeySet{}
	err = json.NewDecoder(fileReader).Decode(&keySet)
	if err != nil {
		return nil, err
	}
	return &keySet, nil
}

func LoadJSONWebKeySetFromURL(url string) (*jose.JSONWebKeySet, error) {
	var client *http.Client
	if IgnoreSSL {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client = &http.Client{Transport: tr}
	} else {
		client = http.DefaultClient
	}
	if resp, err := client.Get(url); err != nil {
		return nil, err
	} else {
		keySet := jose.JSONWebKeySet{}
		err := json.NewDecoder(resp.Body).Decode(&keySet)
		if err != nil {
			return nil, err
		}
		return &keySet, nil
	}
}

func ConvertToPEMBlock(key interface{}) (*pem.Block, error) {
	switch k := key.(type) {
	case *rsa.PublicKey:
		return &pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(k)}, nil
	case *ecdsa.PublicKey:
		bytes, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return nil, err
		}
		return &pem.Block{Type: "EC PUBLIC KEY", Bytes: bytes}, nil
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}, nil
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, err
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}, nil
	default:
		return nil, errors.New("unrecognized key type")
	}
}
