all: env verify build vet test

env:
	go env

verify:
	go mod verify

build:
	go build ./...
	go build

vet:
	go vet ./...
	go vet

test:
	go test -coverprofile=cov.out ./...

coverage: test
	go tool cover -html cov.out -o cov.html
