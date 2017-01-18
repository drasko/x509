package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"

	"pokitdok/x509"
)

func generatePrivateKey(secret string) ([]byte, error) {

	k, err := x509.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("error generating private key: %v", err)
	}

	b, err := x509.EncodePrivateKey(k, []byte(secret))
	if err != nil {
		return nil, fmt.Errorf("error generating private key: %v", err)
	}

	return b, nil
}

func extractPublicKey(r io.Reader, secret string) ([]byte, error) {

	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("error extracting public key: %v", err)
	}

	k, err := x509.ParsePrivateKey(b, []byte(secret))
	if err != nil {
		return nil, fmt.Errorf("error extracting public key: %v", err)
	}

	p, err := x509.EncodePublicKey(&k.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("error extracting public key: %v", err)
	}

	return p, nil
}

func encryptPrivateKey(r io.Reader, secret string) ([]byte, error) {

	if len(secret) == 0 {
		return nil, fmt.Errorf("no secret provided for encrypting private key")
	}

	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("error encrypting private key: %v", err)
	}

	k, err := x509.ParsePrivateKey(b, nil)
	if err != nil {
		return nil, fmt.Errorf("error encrypting private key: %v", err)
	}

	p, err := x509.EncodePrivateKey(k, []byte(secret))
	if err != nil {
		return nil, fmt.Errorf("error encrypting private key: %v", err)
	}

	return p, nil
}

func decryptPrivateKey(r io.Reader, secret string) ([]byte, error) {

	if len(secret) == 0 {
		return nil, fmt.Errorf("no secret provided for decrypting private key")
	}

	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("error decrypting private key: %v", err)
	}

	k, err := x509.ParsePrivateKey(b, []byte(secret))
	if err != nil {
		return nil, fmt.Errorf("error decrypting private key: %v", err)
	}

	p, err := x509.EncodePrivateKey(k, nil)
	if err != nil {
		return nil, fmt.Errorf("error decrypting private key: %v", err)
	}

	return p, nil
}

var (
	BuildHash string
	BuildDate string
	Version   = "0.0.1"
)

func main() {

	usage := `Utility for generating ECDSA keys; %s

Usage:

	key command [arguments]

Commands:

	gen	generates new private key
	pub	extracts public key from private key read from stdin
	encrypt	encrypts unencrypted private key read from stdin
	decrypt	decrypts encrypted private key read from stdin

Arguments:

`
	f := flag.NewFlagSet("common", flag.ExitOnError)
	f.Usage = func() {
		fmt.Fprintf(os.Stderr, usage, fmt.Sprint("v: ", Version, " ", BuildHash, " ", BuildDate))
		f.PrintDefaults()
		fmt.Fprintln(os.Stderr, "")
	}

	secret := f.String("secret", "", "if provided, used to encrypt / decrypt private key")

	if len(os.Args) < 2 {
		f.Usage()
		os.Exit(1)
	}

	f.Parse(os.Args[2:])

	var b []byte
	var err error

	switch os.Args[1] {
	case "gen":
		b, err = generatePrivateKey(*secret)
	case "pub":
		b, err = extractPublicKey(os.Stdin, *secret)
	case "encrypt":
		b, err = encryptPrivateKey(os.Stdin, *secret)
	case "decrypt":
		b, err = decryptPrivateKey(os.Stdin, *secret)
	default:
		f.Usage()
		os.Exit(1)
	}

	if err != nil {
		log.Fatal(err)
	}

	fmt.Print(string(b))
	return
}
