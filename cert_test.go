package x509

import (
	"fmt"
	"testing"
	"time"
)

var _ = fmt.Println

const CERT = `-----BEGIN CERTIFICATE-----
MIIBeDCCAR6gAwIBAgIQDpiJ/E8KcFGaQ1vzW1uwBzAKBggqhkjOPQQDAjATMREw
DwYDVQQKEwhhY21lIGluYzAeFw0xNjA4MDQxOTAwNDJaFw0xNjA4MDQyMDAwNDJa
MBMxETAPBgNVBAoTCGFjbWUgaW5jMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
uNVox7+/8lEOPMNa5T99s/CI/tNqJ6g8EuuEbB1BK615OV8p3tHvDJeI/qBJ86KU
PSi/wny5cbnOFQa7lr3yNqNUMFIwDgYDVR0PAQH/BAQDAgKkMBMGA1UdJQQMMAoG
CCsGAQUFBwMBMA8GA1UdEwEB/wQFMAMBAf8wGgYDVR0RBBMwEYIJbG9jYWxob3N0
hwTAqGNkMAoGCCqGSM49BAMCA0gAMEUCIGSyIHRzfgNXfC4HytqeYsrSoXTr/epK
s0WoKiMvH9t2AiEA/jQqPb836kn83ydnuhF3pdUrrJDTwDmd1yaEL5XCJQA=
-----END CERTIFICATE-----`

var args = &Args{
	Organization: "acme inc",
	Hosts:        "localhost,192.168.99.100",
	DateFrom:     time.Now().UTC(),
	DateTo:       time.Now().UTC().Add(1 * time.Hour),
}

func TestGenerateSelfSignedCert(t *testing.T) {
	priv, _ := GeneratePrivateKey()
	_, err := GenerateSelfSignedCert(priv, args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEncodeCert(t *testing.T) {
	priv, _ := GeneratePrivateKey()
	cert, _ := GenerateSelfSignedCert(priv, args)
	b := EncodeCert(cert)
	fmt.Println(string(b))
}

func TestParseCert(t *testing.T) {
	c, err := ParseCert([]byte(CERT))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Issuer.Organization[0] != args.Organization {
		t.Fatalf("expected %q got %q", args.Organization, c.Issuer.Organization[0])
	}
}
