VERSION ?= $(shell git describe --tags --abbrev=0 | sed 's/v//')
DEST ?= ./bin
SUFFIX?=""
TARGET_OS=linux darwin
TARGET_ARCH=amd64

export CGO_ENABLED=0

build:
	@echo "==> Build binaries..."
	go build -v -ldflags "-s -w -X main.version=${VERSION}" -o ${DEST}/secret-man${SUFFIX} main.go

dist:
	for GOOS in ${TARGET_OS}; do \
		for GOARCH in ${TARGET_ARCH}; do \
			GOOS=$$GOOS GOARCH=$$GOARCH SUFFIX=-v${VERSION}-$$GOOS-$$GOARCH make build; \
		done \
	done \

bump-tag:
	TAG=$$(echo "v${VERSION}" | awk -F. '{$$NF = $$NF + 1;} 1' | sed 's/ /./g'); \
	git tag $$TAG; \
	git push && git push --tags

release: dist
	@echo "==> Create github release and upload files..."

	-github-release release \
		--user servehub \
		--repo secret-man \
		--tag v${VERSION}

	for GOOS in ${TARGET_OS}; do \
		for GOARCH in ${TARGET_ARCH}; do \
			github-release upload \
				--user servehub \
				--repo secret-man \
				--tag v${VERSION} \
				--name secret-man-v${VERSION}-$$GOOS-$$GOARCH \
				--file ${DEST}/secret-man-v${VERSION}-$$GOOS-$$GOARCH \
				--replace; \
		done \
	done \
