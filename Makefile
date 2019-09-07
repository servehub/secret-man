VERSION ?= $(shell git describe --tags --abbrev=0 | sed 's/v//')
DEST ?= ./bin

export CGO_ENABLED=0

build:
	@echo "==> Build binaries..."
	go build -v -ldflags "-s -w -X main.version=${VERSION}" -o ${DEST}/secret-man main.go

dist:
	GOOS=linux GOARCH=amd64 make build

bump-tag:
	TAG=$$(echo "v${VERSION}" | awk -F. '{$$NF = $$NF + 1;} 1' | sed 's/ /./g'); \
	git tag $$TAG; \
	git push && git push --tags
