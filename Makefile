BINARY  := rateguard
PKG     := ./cmd/rateguard
IMAGE   ?= rateguard:latest
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test lint run demo docker clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) $(PKG)

# Redis-backed tests run when a server is reachable; point REDIS_TEST_ADDR at it.
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
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE) .

clean:
	rm -f $(BINARY)
