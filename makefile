all: build vet test

build:
	go build ./...
	go build

vet:
	go vet ./...
	go vet

test:
	go test ./...
