package main

import (
	"bytes"
	"fmt"
	"testing"
)

var _ = fmt.Println

const (
	ENC = `-----BEGIN EC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,e457c5ea6ddb75a996753d3af72a3c8d

C8X4ArV9Xq5Bv/jGBCqIqPv+MnaONLFWu0XAfRWuVqyySzmL8wuxBVIO1wGw2M6i
5NpzpUqWD7eXaK3qyz5sJznZh15XwT15ua8r1sBD2QE/NDH0nJRyIMBCZME1vHbA
pStC4yJQQWVeFR/T29yYMPpjzSW1hHkbbhtO6CV7ePY=
-----END EC PRIVATE KEY-----
`
	DEC = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIGkQaJFRcqFcxWPNZqNpCPYJBCY9OYcETcHQrl/ut1tLoAoGCCqGSM49
AwEHoUQDQgAEv1cZ/pDg6LdZCu4CmjQ5XU22ymeE9eC5hVpVl0v80a/gqFMFbMrw
/QEKc7UA99WfbzFv1zq8S6z/KjVin8sSdA==
-----END EC PRIVATE KEY-----
`
	PUB = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEv1cZ/pDg6LdZCu4CmjQ5XU22ymeE
9eC5hVpVl0v80a/gqFMFbMrw/QEKc7UA99WfbzFv1zq8S6z/KjVin8sSdA==
-----END PUBLIC KEY-----
`
	SECRET = "foobar"
)

func TestGeneratePrivateKey(t *testing.T) {
	_, err := generatePrivateKey(SECRET)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExtractPrivateKey(t *testing.T) {
	r := bytes.NewBufferString(ENC)
	b, err := extractPublicKey(r, SECRET)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(b) != PUB {
		t.Fatalf("extracted public key not as expected:\n%q\n%q", string(b), PUB)
	}
}

func TestEncryptPublicKey(t *testing.T) {
	r := bytes.NewBufferString(DEC)
	_, err := encryptPrivateKey(r, SECRET)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecryptPublicKey(t *testing.T) {
	r := bytes.NewBufferString(ENC)
	b, err := decryptPrivateKey(r, SECRET)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(b) != DEC {
		t.Fatalf("decrypted private key not as expected:\n%q\n%q", string(b), DEC)
	}
}
