SHELL := /bin/bash

HASH := $(shell git rev-parse --short head)
DATE := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')

.PHONY: install
install:
	go install \
		-race \
		-ldflags '-X main.BuildHash=$(HASH) -X main.BuildDate=$(DATE)' \
		pokitdok/x509/cmd/key \
		pokitdok/x509/cmd/cert \

#.PHONY: upload
#upload: install
#	aws s3 cp $(GOPATH)/bin/key s3://binaries-and-debs/bin/darwin/
#	aws s3 cp $(GOPATH)/bin/cert s3://binaries-and-debs/bin/darwin/
