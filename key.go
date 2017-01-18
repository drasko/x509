package x509

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

func GeneratePrivateKey() (*ecdsa.PrivateKey, error) {

	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %s", err)
	}

	return k, nil
}

func EncodePrivateKey(k *ecdsa.PrivateKey, secret []byte) ([]byte, error) {

	b, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil, fmt.Errorf("error marshaling private EC key: %v", err)
	}

	block := &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}

	if len(secret) > 0 {
		block, err = x509.EncryptPEMBlock(rand.Reader, "EC PRIVATE KEY", b, secret, x509.PEMCipherAES256)
		if err != nil {
			return nil, fmt.Errorf("error encrypting PEM block for private key: %v", err)
		}
	}

	return pem.EncodeToMemory(block), nil
}

func EncodePublicKey(k *ecdsa.PublicKey) ([]byte, error) {

	b, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		return nil, fmt.Errorf("error marshaling public PKIX key: %v", err)
	}

	block := &pem.Block{Type: "PUBLIC KEY", Bytes: b}
	return pem.EncodeToMemory(block), nil
}

func ParsePrivateKey(p []byte, secret []byte) (*ecdsa.PrivateKey, error) {

	block, _ := pem.Decode(p)
	if block == nil {
		return nil, errors.New("failed to extract a data block from pem")
	}

	if block.Type != "EC PRIVATE KEY" {
		return nil, fmt.Errorf("extected EC PRIVATE KEY block, got: %v", block.Type)
	}

	b := block.Bytes
	if x509.IsEncryptedPEMBlock(block) {
		var err error
		b, err = x509.DecryptPEMBlock(block, secret)
		if err != nil {
			return nil, fmt.Errorf("error decrypting PEM block: %v", err)
		}
	}

	key, err := x509.ParseECPrivateKey(b)
	if err != nil {
		return nil, fmt.Errorf("failed to parse esdsa private key: %v", err)
	}

	return key, nil
}

func ParsePublicKey(p []byte) (*ecdsa.PublicKey, error) {

	block, _ := pem.Decode(p)
	if block == nil {
		return nil, errors.New("failed to extract a data block from pem")
	}

	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("extected PUBLIC KEY block, got: %v", block.Type)
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing public key: %v", err)
	}

	e, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("expected *ecdsa.PublicKey, got %T", key)
	}

	return e, nil
}
