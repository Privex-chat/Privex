/// <reference types="vitest/config" />
import { defineConfig } from "vitest/config";
import { loadEnv } from "vite";
import react from "@vitejs/plugin-react";
import wasm from "vite-plugin-wasm";
import topLevelAwait from "vite-plugin-top-level-await";
import { VitePWA } from "vite-plugin-pwa";

// Strict Content Security Policy (docs 9.5). Delivered as an HTTP response
// header (never a <meta> tag — meta silently ignores frame-ancestors, sandbox,
// and report-to). In production Caddy sets the header; in dev/preview Vite's
// server.headers does it.
const CSP = [
  "default-src 'none'",
  "script-src 'self' 'wasm-unsafe-eval'", // WASM, no inline JS
  "connect-src 'self' wss://*.privex.chat",
  "img-src 'self' blob: data:",
  "style-src 'self'",
  "font-src 'self'",
  "worker-src 'self' blob:",
  "manifest-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
  "upgrade-insecure-requests",
].join("; ");

// docs 9.5 HTTP security headers (dev server + preview; production is set by Caddy).
const securityHeaders = {
  "Content-Security-Policy": CSP,
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Embedder-Policy": "require-corp",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "X-Frame-Options": "DENY",
};

export default defineConfig(({ mode }) => {
  // Backend (Rust server) the dev proxy forwards to. Override per machine via
  // VITE_BACKEND_URL in apps/web/.env (e.g. http://192.168.1.50:8080). The app
  // always uses relative paths (same-origin), so changing this needs no CORS.
  // VITE_DEV_PORT moves the dev server off 3000.
  const env = loadEnv(mode, process.cwd(), "");
  const backend = env.VITE_BACKEND_URL || "http://localhost:8080";
  const devPort = Number(env.VITE_DEV_PORT) || 3000;

  return {
    plugins: [
      react(),
      wasm(),
      topLevelAwait(),

      VitePWA({
        // injectManifest: our hand-written src/sw.ts (background sync + push) is the
        // SW; Workbox only stamps the precache manifest into it. generateSW can't host
        // custom event handlers.
        strategies: "injectManifest",
        srcDir: "src",
        filename: "sw.ts",
        registerType: "autoUpdate",
        includeAssets: ["favicon.ico", "icons/logo512.svg", "icons/maskable192.webp"],
        manifest: {
          name: "Privex",
          short_name: "Privex",
          description: "True zero-knowledge private communication",
          start_url: "/",
          display: "standalone",
          background_color: "#0a0a0a",
          theme_color: "#0a0a0a",
          display_override: ["window-controls-overlay", "standalone"],
          categories: ["communication", "security"],
          icons: [
            { src: "/favicon.ico", sizes: "48x48", type: "image/x-icon" },
            { src: "/icons/logo512.svg", sizes: "512x512", type: "image/svg+xml" },
            {
              src: "/icons/maskable192.webp",
              sizes: "192x192",
              type: "image/webp",
              purpose: "maskable",
            },
          ],
        },
        injectManifest: {
          // Precache the app shell + WASM so crypto works fully offline (docs 9.3).
          globPatterns: ["**/*.{js,css,html,svg,wasm,ico,webp}"],
          maximumFileSizeToCacheInBytes: 6 * 1024 * 1024,
        },
      }),
    ],
    // Workers (crypto SharedWorker, Nym worker) are ES modules and may use WASM.
    worker: {
      format: "es",
      plugins: () => [wasm(), topLevelAwait()],
    },
    build: {
      sourcemap: false, // no source maps in production
      // Vite's default output uses content hashes → deterministic / reproducible.
    },
    server: {
      allowedHosts: ["privex.chat"],
      port: devPort,
      headers: securityHeaders,
      // Dev only: forward API calls to the configured backend. In prod Caddy serves
      // the API same-origin, so the app always uses relative paths.
      proxy: {
        "/auth": backend,
        "/keys": backend,
        "/recovery": backend,
        "/messages": backend,
        "/blobs": backend,
        "/health": backend,
        "/v1": { target: backend, ws: true },
      },
    },
    preview: { headers: securityHeaders },
    test: {
      environment: "node",
      setupFiles: ["./src/test/setup.ts"],
      include: ["src/**/*.test.ts"],
    },
  };
});
