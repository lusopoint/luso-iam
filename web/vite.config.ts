import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwind from '@tailwindcss/vite'
import { VitePWA } from 'vite-plugin-pwa'

// `base: "/admin/"` so all asset URLs in the production index.html are
// prefixed with /admin/assets/..., matching where the Go embed handler
// serves them. The dev server runs at /admin/* too, proxying API calls
// to the Go backend on :8080.
export default defineConfig({
  base: '/admin/',
  plugins: [
    react(),
    tailwind(),
    // VitePWA generates the manifest, registers a workbox service worker,
    // and emits the necessary <link> tags into index.html at build time.
    //
    // scope is "/admin/" because that's where the SPA lives. Service
    // workers can only control their own scope, and we don't want the
    // SW to intercept /cas/login, /oauth2/*, or the well-known endpoints.
    VitePWA({
      registerType: 'prompt',
      // We register from app code (src/lib/pwa.ts) so we can surface
      // "new version available" to the user as a toast instead of
      // silently reloading mid-edit. injectRegister:false stops the
      // plugin from injecting its own registration script.
      injectRegister: false,
      strategies: 'generateSW',
      scope: '/admin/',
      base: '/admin/',
      includeAssets: ['icon.svg', 'icon-180.png'],
      manifest: {
        id: '/admin/',
        name: 'IAM Server — Admin',
        short_name: 'IAM Admin',
        description:
          'Administer users, OIDC clients, CAS services, audit log, and signing keys.',
        start_url: '/admin/',
        scope: '/admin/',
        display: 'standalone',
        orientation: 'any',
        background_color: '#0b0f19',
        theme_color: '#0284c7',
        icons: [
          { src: 'icon-192.png', sizes: '192x192', type: 'image/png' },
          { src: 'icon-512.png', sizes: '512x512', type: 'image/png' },
          {
            src: 'icon-maskable-512.png',
            sizes: '512x512',
            type: 'image/png',
            purpose: 'maskable',
          },
        ],
        categories: ['productivity', 'developer', 'utilities'],
      },
      workbox: {
        globPatterns: ['**/*.{js,css,html,svg,png,ico,webmanifest}'],
        globIgnores: ['**/*.map'],
        navigateFallback: '/admin/index.html',
        navigateFallbackDenylist: [/^\/admin\/v1/],
        runtimeCaching: [
          {
            // API calls: try the network, but fall back fast if offline
            // so the UI can render a meaningful error instead of hanging.
            urlPattern: /\/admin\/v1\/.*/,
            handler: 'NetworkFirst',
            options: {
              cacheName: 'iam-admin-api',
              networkTimeoutSeconds: 5,
              expiration: { maxEntries: 100, maxAgeSeconds: 60 * 5 },
              cacheableResponse: { statuses: [0, 200] },
            },
          },
        ],
      },
      devOptions: { enabled: false },
    }),
  ],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: true,
  },
  server: {
    port: 5173,
    proxy: {
      '/admin/v1': 'http://localhost:8080',
      '/cas': 'http://localhost:8080',
      '/oauth2': 'http://localhost:8080',
      '/oauth': 'http://localhost:8080',
      '/mfa': 'http://localhost:8080',
      '/.well-known': 'http://localhost:8080',
      '/healthz': 'http://localhost:8080',
    },
  },
})
