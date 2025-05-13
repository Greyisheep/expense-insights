BINARY_NAME=efms-service

.PHONY: all build run test clean deps lint

all: build

build:
	@echo "Building $(BINARY_NAME)..."
	@go build -o ./bin/$(BINARY_NAME) ./cmd/efms-service

run:
	@echo "Running $(BINARY_NAME)..."
	@./bin/$(BINARY_NAME)

test:
	@echo "Running tests..."
	@go test -v ./...

clean:
	@echo "Cleaning..."
	@go clean
	@rm -f ./bin/$(BINARY_NAME)

deps:
	@echo "Installing dependencies..."
	@go mod tidy
	@go mod download

lint:
	@echo "Linting..."
	# Add your linter command here, e.g.:
	# @golangci-lint run

# Ensure the bin directory exists for the build target
./bin/$(BINARY_NAME): 
	@mkdir -p ./bin
