all: build vet test

build:
	go build ./...
	go build

vet:
	go vet ./...
	go vet

test:
	go test -race -coverprofile=cov.out ./...

coverage: test
	go tool cover -html cov.out -o cov.html
