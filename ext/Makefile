.PHONY: all
all: vet fmt lint build

.PHONY: vet
vet:
	go vet ./...

.PHONY: fmt
fmt:
	go fmt ./...

.PHONY: lint
lint:
	golangci-lint run ./...

.PHONY: build
build:
	go build -o ../age.so -buildmode=c-shared age.go

.PHONY: clean
clean:
	rm -f ../age.so ../age.h
