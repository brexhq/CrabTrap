# Contributing to CrabTrap

Thank you for your interest in contributing to CrabTrap! This document explains how to get started, the development workflow, and the guidelines we follow.

## Code of Conduct

Be respectful and constructive. We want CrabTrap to be a welcoming project for everyone.

## Getting Started

### Prerequisites

- **Go 1.27.3+**
- **Node.js 22+** and npm
- **Docker** (for the PostgreSQL development database)
- **Make**
- **[GoReleaser](https://goreleaser.com/)** (optional, for testing releases locally)

### Setting Up Your Environment

```bash
# Clone the repository
git clone https://github.com/brexhq/CrabTrap.git
cd CrabTrap

# Generate CA certificates
make gen-certs

# Build the project (compiles the web UI and Go binary)
make build
```

### Running Locally

```bash
# Recommended: start both backend and frontend with hot-reload
make dev

# Or run only the backend in development mode
make dev-backend
```

See the [README](README.md) for more details on configuration and usage.

## Development Workflow

1. **Fork** the repository and create a branch from `main`.
2. **Make your changes** — keep them focused and aligned with existing package boundaries.
3. **Run the tests** before submitting:

   ```bash
   make test
   ```

   `make test` runs `make lint` (Go vet + staticcheck) followed by `go test -race -p 1 ./...`.

4. **Build the frontend** if you changed anything under `web/src/`:

   ```bash
   make build-web
   ```

5. **Open a pull request** against `main` with a clear description of what changed and why.

## Project Structure

```
crabtrap/
├── cmd/gateway/          # Main entry point, admin API wiring, web UI serving
├── internal/             # Core packages (proxy, approval, config, judge, llm, eval, …)
├── pkg/types/            # Shared exported types
├── web/src/              # React + TypeScript admin UI
├── config/               # Configuration files and examples
└── certs/                # TLS certificates (generated, not committed)
```

Refer to [AGENTS.md](AGENTS.md) for a compact repository map and working conventions aimed at automated contributors.

## Coding Guidelines

### Go

- Follow the conventions already present in the codebase.
- Run `make fmt` to format code and `make lint` to catch issues before committing.
- Prefer focused fixes over broad refactors unless the task explicitly requires wider changes.

### TypeScript / React (web UI)

- The frontend lives in `web/src/` and is built with Vite.
- Run `make build-web` to verify that TypeScript compiles and the bundle succeeds.
- The Vite dev server proxies `/admin` and `/health` to `http://localhost:8081`.

### General

- Keep API paths compatible with the current frontend proxy and backend routes.
- Do not commit generated certificates, local secrets, or copied credential files.
- When runtime configuration is needed, start from `config/gateway.yaml.example`.

## Testing

- **Unit tests**: `go test ./...` (or `make test` for the full lint + test pass).
- If you change proxying, TLS, config loading, or approval flows, do a quick runtime sanity check with `make run` or `make run-dev` when feasible.
- `web/dist`, `cmd/gateway/web/dist`, and the root `gateway` binary are build artifacts — do not hand-edit them.

## Submitting a Pull Request

1. Ensure `make test` and `make build-web` pass.
2. Write a clear PR title and description explaining the motivation and scope.
3. Reference any related GitHub issues.
4. Keep PRs small and reviewable when possible — one logical change per PR is ideal.

## CI/CD

### GitHub Actions

Every push and pull request runs the **CI** workflow (`.github/workflows/ci.yml`):

- **Lint** — `go vet` and `staticcheck`
- **Test** — `go test -race -p 1 ./...` with a PostgreSQL service container
- **Docker Build** — verifies `Dockerfile.goreleaser` builds cleanly

### Releasing with GoReleaser

Releases are managed by [GoReleaser](https://goreleaser.com/) (`.goreleaser.yaml`). When a `v*` tag is pushed, the **Release** workflow (`.github/workflows/release.yml`) runs GoReleaser to:

1. Build `gateway` binaries for linux/darwin (amd64/arm64)
2. Generate a changelog from commit history
3. Create a GitHub Release with binary archives and checksums
4. Build and push multi-arch Docker images to `quay.io/brexhq/crabtrap`

#### Creating a release

```bash
git tag v1.2.3
git push origin v1.2.3
```

The workflow handles everything else automatically. GoReleaser generates a changelog from commits since the previous tag, grouped by type (Features, Bug Fixes, Security, Other Changes).

#### Writing release notes

The release header in `.goreleaser.yaml` provides a standard template that appears above the auto-generated changelog. To add release-specific notes (highlights, breaking changes, migration instructions), edit the GitHub Release on the web after the workflow completes.

#### Commit message conventions

The changelog is grouped automatically based on commit message prefixes:

| Prefix | Group |
|--------|-------|
| `feat:` / `feat(scope):` | Features |
| `fix:` / `bug:` | Bug Fixes |
| `Security` (anywhere in message) | Security |
| Everything else | Other Changes |

Commits prefixed with `docs:`, `test:`, `ci:`, and merge commits are excluded from the changelog entirely. Use descriptive commit messages — the first line becomes the changelog entry.

#### Testing locally

Install GoReleaser, then:

```bash
# Validate the config
goreleaser check

# Dry-run a snapshot build (no publish, no Docker push)
goreleaser release --snapshot --clean --skip=docker

# Full local release (requires docker login to quay.io)
goreleaser release --clean
```

**Note:** GoReleaser requires a clean git working tree and a tag on the current commit.

## Reporting Issues

Open an issue at <https://github.com/brexhq/CrabTrap/issues> with:

- A clear title and description.
- Steps to reproduce the problem.
- Expected vs. actual behavior.
- Relevant logs, config snippets, or screenshots.

## License

By contributing to CrabTrap you agree that your contributions will be licensed under the [MIT License](LICENSE).
