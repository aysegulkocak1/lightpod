.PHONY: all build check fmt vet test cross integration integration-root clean

# Target hardware is arm; this machine probably isn't. Plain `go build` leaves
# the arm files out on a build tag, so cross is the only thing that compiles
# them.
ARCHS := arm64 arm

all: build

build:
	go build -o lightpod ./cmd/lightpod

# Run before pushing.
check: fmt vet test cross

fmt:
	@out=$$(gofmt -l .); \
	if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

vet:
	go vet ./...
	go vet -tags integration ./test/...
	go vet -tags integration_root ./test/...

test:
	go test ./...

cross:
	@for arch in $(ARCHS); do \
		echo "GOARCH=$$arch"; \
		GOOS=linux GOARCH=$$arch go build ./... || exit 1; \
		GOOS=linux GOARCH=$$arch go vet ./... || exit 1; \
	done

# Needs newuidmap and an /etc/subuid range for this user.
integration: rootfs/check
	go test -count=1 -tags integration ./test/...

# Separate because it needs root, so it can't go in check.
integration-root: rootfs/check
	sudo -E env "PATH=$$PATH" go test -count=1 -tags integration_root ./test/...

rootfs/check:
	mkdir -p rootfs
	CGO_ENABLED=0 go build -o rootfs/check ./test/isolationcheck

clean:
	rm -rf lightpod rootfs bundle
