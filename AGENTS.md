# AGENTS.md

## Scope

These instructions apply to the whole repository. Keep changes small, practical, and aligned with the existing package boundaries.

## Repository Map

- `cmd/gateway`: main binary, admin API wiring, and web UI serving.
- `internal/`: core gateway packages such as `approval`, `proxy`, `config`, `notifications`, `judge`, `llm`, and `eval`.
- `pkg/types`: shared exported types.
- `web/src`: React + TypeScript admin UI.
- `web/dist` and the root `gateway` binary are build artifacts. Do not hand-edit generated output.

## Working Conventions

- Prefer focused fixes over broad refactors unless the task explicitly requires wider changes.
- Follow existing Go and TypeScript patterns in the surrounding code before introducing new structure.
- Keep API paths compatible with the current frontend proxy and backend routes. The Vite dev server proxies `/admin` and `/health` to `http://localhost:8081`.
- When runtime configuration is needed, start from `config/gateway.yaml.example`.
- Do not commit generated certs, local secrets, or copied credential files.

## Build And Run

- Full-stack development: `make dev`
- Backend in development mode: `make run-dev` or `make dev-backend`
- Production-style build (binary + `web/dist` on disk): `make build`
- Frontend build only: `make build-web`
- Generate local CA certs for manual proxy testing: `make gen-certs`

## Testing Instructions

- Run `make test` for the default verification pass on code changes.
- `make test` generates local certs (`make gen-certs`), runs `make lint`, then `go test -race -p 1 ./...`.
- Run `make build-web` after frontend changes to catch TypeScript and bundling regressions.
- Run `make lint` directly if you only need the Go vet and `staticcheck` pass.
- If you change proxying, TLS, config loading, or approval flows, do a quick runtime sanity check with `make run` or `make run-dev` when feasible.

## Logging

- Use `log/slog` for all logging. Do not use the `log` or `fmt.Printf` packages for log output.
- Use structured key-value pairs: `slog.Info("message", "key", value)` rather than format strings.
- Choose the appropriate level: `slog.Info` for normal operations, `slog.Warn` for recoverable issues, `slog.Error` for failures.
- When a fatal exit is needed, use `slog.Error(...)` followed by `os.Exit(1)`. Do not use `log.Fatalf`.
- Never log sensitive data (Authorization headers, cookies, API keys, request/response bodies) to file or stdout. The audit logger strips these fields automatically; do not re-introduce them via ad-hoc log calls.

## Notes

- Use `make build` for the production binary and UI.
- If you need a local config file, copy from `config/gateway.yaml.example` rather than inventing a new format.
