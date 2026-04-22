# Resolve the DATABASE_URL at recipe execution time (after db-up has run).
# docker compose port returns the actual host port Docker assigned to postgres.
# NOTE: DB_URL uses shell command substitution ($$(...)) so it only expands correctly
# inside recipe lines. Always use DATABASE_URL=$(DB_URL) as a recipe-level prefix.
DB_URL = postgres://crabtrap:secret@localhost:$$(docker compose port postgres 5432 | cut -d: -f2)/crabtrap

.PHONY: build build-go run run-dev test clean setup install-ca gen-certs fix-trust help build-web build-web-for-dev dev-web dev dev-backend db-up db-down db-reset import

# Build the gateway with embedded web UI (default)
build: build-web
	@echo "Copying web UI to embed location..."
	@rm -rf cmd/gateway/web
	@mkdir -p cmd/gateway/web
	@cp -r web/dist cmd/gateway/web/dist
	@echo "Building gateway with embedded web UI..."
	go build -o gateway cmd/gateway/*.go
	@echo "✓ Gateway built successfully!"

# Build Go binary only (assumes web/dist already exists, used by Docker)
build-go:
	@echo "Copying web UI to embed location..."
	@rm -rf cmd/gateway/web
	@mkdir -p cmd/gateway/web
	@cp -r web/dist cmd/gateway/web/dist
	@echo "Building gateway with optimizations..."
	go build -ldflags="-s -w" -o gateway cmd/gateway/*.go
	@echo "✓ Go binary built successfully!"

# Build with optimizations (builds web first, then Go binary)
build-prod: build-web build-go

# Build web UI
build-web:
	@echo "Building web UI..."
	cd web && npm install && npm run build

# Run web UI development server only
dev-web:
	@echo "Starting web UI development server..."
	@echo "→ Frontend: http://localhost:3000"
	@echo "→ Make sure backend is running on http://localhost:8081"
	@echo ""
	cd web && npm run dev

# Start the development database (Postgres in Docker)
db-up:
	@docker compose up -d postgres >&2
	@echo "Waiting for Postgres to be ready..." >&2
	@docker compose exec postgres sh -c 'until pg_isready -U crabtrap -d crabtrap; do sleep 1; done' >/dev/null 2>&1

# Stop the development database
db-down:
	docker compose down

# Drop and recreate the database, then re-apply migrations
db-reset: db-up
	docker compose exec postgres psql -U crabtrap -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='crabtrap' AND pid <> pg_backend_pid();" postgres
	docker compose exec postgres psql -U crabtrap -c "DROP DATABASE IF EXISTS crabtrap;" postgres
	docker compose exec postgres psql -U crabtrap -c "CREATE DATABASE crabtrap;" postgres

# Seed credentials from data/credentials/mappings.json into the database
import: db-up
	DATABASE_URL=$(DB_URL) go run scripts/import_mappings.go

# Run both backend and frontend in development mode (RECOMMENDED)
dev: db-up
	@echo "=========================================="
	@echo "Starting development environment..."
	@echo "=========================================="
	@echo ""
	@echo "→ Database:    $(DB_URL)"
	@echo "→ Backend API: http://localhost:8081"
	@echo "→ Frontend UI: http://localhost:3000 (with HMR)"
	@echo ""
	@make -j2 dev-web run-dev

# Alternative: Run backend in dev mode serving from filesystem
# Build minimal web UI for dev mode (just to satisfy embed requirement)
build-web-for-dev:
	@echo "Setting up web UI for development..."
	@mkdir -p cmd/gateway/web/dist
	@echo '<!DOCTYPE html><html><body><p>Dev mode - use http://localhost:3000</p></body></html>' > cmd/gateway/web/dist/index.html
	@echo "✓ Web UI placeholder created"

# This serves the UI from web/dist/ without embedding, allowing manual rebuilds
dev-backend:
	@echo "Starting backend in development mode..."
	@echo "Serving web UI from web/dist/ (filesystem)"
	@echo "Run 'make build-web' after making frontend changes"
	@make run-dev

# Full setup (for first time users)
setup: gen-certs build
	@echo ""
	@echo "=========================================="
	@echo "Setup complete!"
	@echo "=========================================="
	@echo ""
	@echo "The gateway is ready to use."
	@echo ""
	@echo "To start the gateway:"
	@echo "  make run"
	@echo ""
	@echo "To test the gateway:"
	@echo "  ./test-proxy.sh"
	@echo ""

# Run the gateway (production mode with embedded web UI)
run: build
	./gateway -config config/gateway.yaml

# Run the gateway in development mode (serves web UI from filesystem)
run-dev: build-web-for-dev
	go build -o gateway cmd/gateway/*.go
	DATABASE_URL=$(DB_URL) ./gateway -config config/gateway.yaml -dev

# Generate CA certificates (with automatic installation)
gen-certs:
	./scripts/generate-certs.sh

# Fix certificate trust issues
fix-trust:
	@if [ ! -f certs/ca.crt ]; then \
		echo "Error: CA certificate not found. Run 'make gen-certs' first."; \
		exit 1; \
	fi
	@echo "Fixing certificate trust settings..."
	@echo "This will install the CA certificate with full system trust."
	@echo ""
	@if [[ "$$OSTYPE" == "darwin"* ]]; then \
		security delete-certificate -c "CrabTrap CA" 2>/dev/null || true; \
		sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain certs/ca.crt; \
		echo ""; \
		echo "✓ Certificate trust fixed!"; \
	elif [[ "$$OSTYPE" == "linux-gnu"* ]]; then \
		sudo cp certs/ca.crt /usr/local/share/ca-certificates/crabtrap.crt; \
		sudo update-ca-certificates; \
		echo ""; \
		echo "✓ Certificate trust fixed!"; \
	else \
		echo "Unsupported platform. Please install certificate manually."; \
		exit 1; \
	fi

# Install CA certificate (legacy - use gen-certs instead)
install-ca:
	@echo "Note: This target is deprecated. Use 'make gen-certs' instead."
	@echo "      The gen-certs target now handles installation automatically."
	@echo ""
	@if [ ! -f certs/ca.crt ]; then \
		echo "Error: CA certificate not found. Run 'make gen-certs' first."; \
		exit 1; \
	fi
	security add-trusted-cert -d -r trustRoot -k ~/Library/Keychains/login.keychain certs/ca.crt
	@echo "CA certificate installed. You may need to restart your browser."

# Print shell exports for the current worktree's env vars.
# Usage: eval $(make print-env)
print-env: db-up
	@echo "export DATABASE_URL=$(DB_URL)"

# Test build
test: lint
	go test -race -p 1 ./...

# Clean build artifacts
clean:
	rm -f gateway
	rm -f certs/ca.key certs/ca.crt
	rm -rf web/dist
	rm -rf web/node_modules

# Format code
fmt:
	go fmt ./...

# Run linter
lint:
	@which staticcheck > /dev/null || (echo "Installing staticcheck..." && go install honnef.co/go/tools/cmd/staticcheck@latest)
	go vet ./...
	staticcheck ./...

# Show help
help:
	@echo "CrabTrap - Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  setup          - Complete first-time setup (generates certs + builds)"
	@echo "  build          - Build the gateway binary (without web UI)"
	@echo "  build-prod     - Build with optimizations (without web UI)"
	@echo "  build-web      - Build the web UI frontend"
	@echo "  run            - Build and run the gateway (production mode)"
	@echo "  run-dev        - Run gateway in dev mode (serves UI from filesystem)"
	@echo "  dev            - Run both backend and frontend with HMR (RECOMMENDED)"
	@echo "  dev-web        - Run web UI development server only"
	@echo "  dev-backend    - Run backend in dev mode only"
	@echo "  gen-certs      - Generate and install CA certificates"
	@echo "  fix-trust      - Fix certificate trust issues"
	@echo "  test           - Run tests"
	@echo "  clean          - Remove build artifacts and certificates"
	@echo "  fmt            - Format Go code"
	@echo "  lint           - Run Go linter"
	@echo "  help           - Show this help message"
	@echo ""
	@echo "Quick start (first time):"
	@echo "  make setup              # Generate certs + build"
	@echo "  make dev                # Start development (recommended)"
	@echo ""
	@echo "Development workflows:"
	@echo "  make dev                # Backend + Frontend with HMR (best DX)"
	@echo "  make dev-backend        # Backend only in dev mode"
	@echo ""
	@echo "Production deployment:"
	@echo "  make build              # Creates single binary with embedded UI"
	@echo "  ./gateway               # Run production binary"
	@echo ""
	@echo "If you get TLS certificate errors:"
	@echo "  make fix-trust"
	@echo ""
