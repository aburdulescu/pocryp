all: build vet test

build:
	go build ./...
	go build

vet:
	go vet ./...
	go vet

test:
	go test -race -cover ./...

coverage:
	go test -coverprofile=cov.out ./...
	go tool cover -html cov.out -o cov.html
