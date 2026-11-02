BINARY  := rateguard
PKG     := ./cmd/rateguard
IMAGE   ?= rateguard:latest

.PHONY: build test lint run demo docker

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o $(BINARY) $(PKG)

test:
	go test -race ./...

lint:
	go vet ./...
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed for:"; echo "$$out"; exit 1; fi

run: build
	RLG_DATA_DIR=./data ./$(BINARY)

demo: build
	RLG_DEMO=true RLG_DATA_DIR=./data-demo ./$(BINARY)

docker:
	docker build -t $(IMAGE) .
