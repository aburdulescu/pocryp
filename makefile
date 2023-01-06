dev: build vet lint test

ci: env verify build vet test

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

lint:
	which golangci-lint || go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	golangci-lint run

test:
	go test -cover -coverprofile=cov.out ./...

coverage: test
	go tool cover -html cov.out -o cov.html
