package x509

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

type Args struct {
	Organization string
	Hosts        string
	DateFrom     time.Time
	DateTo       time.Time
}

func generateTemplate(args *Args) (*x509.Certificate, error) {

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %s", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{args.Organization},
		},
		NotBefore:             args.DateFrom,
		NotAfter:              args.DateTo,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	for _, h := range strings.Split(args.Hosts, ",") {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	return template, nil
}

func GenerateCert(signing *ecdsa.PrivateKey, ca *x509.Certificate, public *ecdsa.PublicKey, args *Args) ([]byte, error) {

	template, err := generateTemplate(args)
	if err != nil {
		return nil, fmt.Errorf("error generating cert template: %v", err)
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, ca, public, signing)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %s", err)
	}

	return cert, nil
}

func GenerateSelfSignedCert(key *ecdsa.PrivateKey, args *Args) ([]byte, error) {

	template, err := generateTemplate(args)
	if err != nil {
		return nil, fmt.Errorf("error generating cert template: %v", err)
	}

	template.KeyUsage |= x509.KeyUsageCertSign
	template.IsCA = true

	cert, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %s", err)
	}

	return cert, nil
}

func EncodeCert(b []byte) []byte {

	p := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b})
	return p
}

func ParseCert(b []byte) (*x509.Certificate, error) {

	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("failed to extract a data block from pem")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("extected CERTIFICATE block, got: %v", block.Type)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	return cert, nil
}
