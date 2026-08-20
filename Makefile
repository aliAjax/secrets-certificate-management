.PHONY: build run test tidy docker-up docker-down cli

build:
	go build ./...

run:
	go run ./cmd/server

cli:
	go run ./cmd/cli

test:
	go test ./...

tidy:
	go mod tidy

docker-up:
	docker compose -f deploy/docker-compose.yml up -d

docker-down:
	docker compose -f deploy/docker-compose.yml down
