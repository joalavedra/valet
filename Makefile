.PHONY: build test lint fmt vet clean

build:
	go build -o valet .

test:
	go test ./...

vet:
	go vet ./...

lint: vet
	@test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)

fmt:
	gofmt -w .

release-snapshot:
	goreleaser release --snapshot --clean

clean:
	rm -f valet coverage.out
