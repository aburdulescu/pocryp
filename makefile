all: verify build vet test

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
