package main

import (
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// serveWebUI returns an HTTP handler for serving the web UI.
// The UI is always served from web/dist on disk; run 'make build-web' to generate it.
func serveWebUI(devMode bool) http.Handler {
	dirs := []string{filepath.Join("web", "dist")}
	if exe, err := os.Executable(); err == nil {
		dirs = append(dirs, filepath.Join(filepath.Dir(exe), "web", "dist"))
	}
	webDistPath, found := findWebDist(dirs)
	if !found {
		slog.Warn("web/dist directory not found, run 'make build-web' first or use 'make dev' for development")
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !devMode {
				http.Error(w, "Web UI not available; run 'make build-web'", http.StatusNotFound)
				return
			}
			if strings.HasPrefix(r.URL.Path, "/admin/") || strings.HasPrefix(r.URL.Path, "/health") {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<!DOCTYPE html>
<html>
<head><title>CrabTrap</title></head>
<body>
	<h1>Development Mode</h1>
	<p>Web UI not built yet. Choose one of:</p>
	<ol>
		<li><strong>Recommended:</strong> Run <code>make dev</code> to start frontend dev server with HMR at http://localhost:3000</li>
		<li>Or build first: <code>make build-web</code></li>
	</ol>
</body>
</html>`))
		})
	}
	mode := "production"
	if devMode {
		mode = "development (live reload)"
	}
	slog.Info("serving web UI from filesystem", "mode", mode, "path", webDistPath)

	fileSystem := http.Dir(webDistPath)
	fsRoot := os.DirFS(webDistPath)

	fileServer := http.FileServer(fileSystem)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If the request is for an API endpoint, don't serve the UI
		if strings.HasPrefix(r.URL.Path, "/admin/") || strings.HasPrefix(r.URL.Path, "/health") {
			http.NotFound(w, r)
			return
		}

		// For SPA routing, serve index.html for non-existent paths.
		// (except for static assets like .js, .css, .png, etc.)
		//
		// API clients do not include "text/html" in their
		// Accept header. When they request an unknown path they should get a JSON 404, not
		// the SPA HTML — which would cause JSON parse errors in those clients.
		path := r.URL.Path
		if path != "/" && !hasFileExtension(path) {
			// Check if file exists
			if _, err := fs.Stat(fsRoot, strings.TrimPrefix(path, "/")); err != nil {
				// File doesn't exist. Only rewrite to index.html for browser requests.
				// Browsers always include "text/html" in their Accept header for page loads.
				if strings.Contains(r.Header.Get("Accept"), "text/html") {
					r.URL.Path = "/"
				} else {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusNotFound)
					w.Write([]byte(`{"error":"not_found"}`))
					return
				}
			}
		}

		// Add cache control headers for static assets
		if hasFileExtension(path) {
			if devMode {
				w.Header().Set("Cache-Control", "no-cache") // No cache in dev mode
			} else {
				w.Header().Set("Cache-Control", "public, max-age=31536000") // 1 year in prod
			}
		} else {
			w.Header().Set("Cache-Control", "no-cache") // Don't cache HTML
		}

		fileServer.ServeHTTP(w, r)
	})
}

// findWebDist returns the first directory containing web/dist assets.
func findWebDist(dirs []string) (string, bool) {
	for _, dir := range dirs {
		if _, err := os.Stat(dir); err == nil {
			return dir, true
		}
	}
	return "", false
}

// hasFileExtension checks if a path has a file extension
func hasFileExtension(path string) bool {
	return strings.Contains(path, ".")
}
