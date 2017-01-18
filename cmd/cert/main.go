package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	"pokitdok/x509"
)

func generateSelfSignedCert(a *Args) {

	b, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		log.Fatal(err)
	}

	key, err := x509.ParsePrivateKey(b, []byte(a.secret))
	if err != nil {
		log.Fatalf("couldn't parse private key: %v", err)
	}

	cert := &x509.Args{
		Organization: a.org,
		Hosts:        a.hosts,
		DateFrom:     a.from,
		DateTo:       a.to,
	}

	c, err := x509.GenerateSelfSignedCert(key, cert)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Print(string(x509.EncodeCert(c)))
	return
}

var (
	BuildHash string
	BuildDate string
	Version   = "0.0.1"
)

type Args struct {
	org    string
	hosts  string
	from   time.Time
	to     time.Time
	secret string
}

func fmtTime(s *string) time.Time {
	t, err := time.Parse("20060102", *s)
	if err != nil {
		log.Fatalf("error parsing date, expecting format YYYYMMDD: %v", err)
	}
	return t
}

func main() {

	usage := `Utility for generating x509 certificates; %s 

Usage:

	cert [arguments] <key.pem

Arguments:

`
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, usage, fmt.Sprint("v: ", Version, " ", BuildHash, " ", BuildDate))
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, "")
	}

	o := flag.String("org", "acme inc", "name of the organization for the cert")
	h := flag.String("hosts", "localhost,127.0.0.1", "ips and names for the cert, comma separated")
	f := flag.String("from", time.Now().UTC().Format("20060102"), "date from which cert is valid")
	t := flag.String("to", time.Now().UTC().Add(24*time.Hour).Format("20060102"), "date to which cert is valid")
	flag.Parse()

	a := &Args{
		org:   *o,
		hosts: *h,
		from:  fmtTime(f),
		to:    fmtTime(t),
	}

	generateSelfSignedCert(a)
}
