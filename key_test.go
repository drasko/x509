package x509

import (
	"fmt"
	"testing"
)

var _ = fmt.Println

const (
	KEY = `-----BEGIN EC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,e457c5ea6ddb75a996753d3af72a3c8d

C8X4ArV9Xq5Bv/jGBCqIqPv+MnaONLFWu0XAfRWuVqyySzmL8wuxBVIO1wGw2M6i
5NpzpUqWD7eXaK3qyz5sJznZh15XwT15ua8r1sBD2QE/NDH0nJRyIMBCZME1vHbA
pStC4yJQQWVeFR/T29yYMPpjzSW1hHkbbhtO6CV7ePY=
-----END EC PRIVATE KEY-----`
	PUB = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0XWodXCNWMf4ZAH49IUwvcVyB66z
HjEqemSBTDesppS+exVoFgOxlm+KhxhjBihlO+2RnlW9SeuDKpdGH0gdLA==
-----END PUBLIC KEY-----`
	RSA = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAo+/dZUfycTHOegA4Kn+F
JC65+Sy+TrbYkpQZb+loQYGEpYPmZ7x999efMwK/rxyuvnF4V/1hTXlVzC4f8vTS
A9o2nGO+X5nAMU3jm2SnUO8NMvFYW4eAwjceSzB+4dmkYeVFEGCjRa4Xu/qHqjEl
PYzQOtv8EEpH9A6IPzZK3tvFYAcrX/Flyi/4qnslgMPd/UPqQWN79XQxQmq4SZme
wegdL/YdpN3UKLhYURp7oJfKQth91Uw14ijmSckS2C8ifDNjLVBoB8XyUuXV1vkM
0JvNRlToG3xsHeWX7YmFK8uKrOYQTP1gnrinv8W0/KyPbiyj6BUKfEoGYGw08gZ5
nwIDAQAB
-----END PUBLIC KEY-----`
)

func TestGeneratePrivateKey(t *testing.T) {
	_, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEncodePrivateKey(t *testing.T) {
	k, _ := GeneratePrivateKey()
	_, err := EncodePrivateKey(k, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, err = EncodePrivateKey(k, []byte("foobar"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEncodePublicKey(t *testing.T) {
	k, _ := GeneratePrivateKey()
	b, err := EncodePublicKey(&k.PublicKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	fmt.Println(string(b))
}

func TestParsePrivateKey(t *testing.T) {
	_, err := ParsePrivateKey([]byte(KEY), nil)
	if err == nil {
		t.Fatal("expected error, didn't get it")
	}
	_, err = ParsePrivateKey([]byte(KEY), []byte("fooXXX"))
	if err == nil {
		t.Fatal("expected error, didn't get it")
	}
	_, err = ParsePrivateKey([]byte(KEY), []byte("foobar"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParsePublicKey(t *testing.T) {
	_, err := ParsePublicKey([]byte(PUB))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expect := "expected *ecdsa.PublicKey, got *rsa.PublicKey"
	_, err = ParsePublicKey([]byte(RSA))
	if err.Error() != expect {
		t.Fatalf("expected: %v, got: %v", expect, err)
	}
}
