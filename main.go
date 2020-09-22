package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"github.com/hashicorp/packer/builder/azure/pkcs12"
	"io/ioutil"
	"log"
	"os"
)

type vaultResponse struct {
	Data certData `json:"data"`
}
type certData struct {
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private_key"`
}

func convert(input certData, pass string) (p12 []byte, err error) {
	priKeyBlock, _ := pem.Decode([]byte(input.PrivateKey))
	if priKeyBlock == nil {
		return p12, errors.New("error decoding private key")
	}

	certBlock, _ := pem.Decode([]byte(input.Certificate))
	if certBlock == nil {
		return p12, errors.New("error decoding certificate")
	}

	var keyObj interface{}
	switch priKeyBlock.Type {
	case "RSA PRIVATE KEY":
		keyObj, err = x509.ParsePKCS1PrivateKey(priKeyBlock.Bytes)
		if err != nil {
			return p12, errors.New("unable to parse private key to native object")
		}
	case "EC PRIVATE KEY":
		keyObj, err = x509.ParseECPrivateKey(priKeyBlock.Bytes)
		if err != nil {
			return p12, errors.New("unable to parse private key to native object")
		}
	default:
		return p12, errors.New(fmt.Sprintf("unsupported key type: %v", priKeyBlock.Type))
	}

	p12, err = pkcs12.Encode(certBlock.Bytes, keyObj, pass)
	return
}

func main() {
	password := flag.String("password", "", "p12 export password")
	output := flag.String("out", "stdout", "export p12 to file")
	flag.Parse()

	inputData, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		log.Fatal(err)
	}

	input := vaultResponse{}
	if err := json.Unmarshal(inputData, &input); err != nil {
		log.Fatal(err)
	}

	if input.Data.PrivateKey == "" || input.Data.Certificate == "" {
		log.Fatal("private key or certificate data cannot be nil")
	}

	p12, err := convert(input.Data, *password)
	if err != nil {
		log.Fatal(err)
	}

	if *output != "stdout" {
		if err := ioutil.WriteFile(*output, p12, 0644); err != nil {
			log.Fatal("error writing to output ", err)
		}
	} else {
		fmt.Println(string(p12))
	}
}
