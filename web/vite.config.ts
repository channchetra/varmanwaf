import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import path from 'path'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      '@': path.resolve(import.meta.dirname, './src'),
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:9080',
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    emptyOutDir: true,
    chunkSizeWarningLimit: 900,
    rollupOptions: {
      output: {
        // Vite 8 only accepts the function form (the object form was removed).
        manualChunks(id) {
          const groups: Array<[string, RegExp]> = [
            ['react', /[\\/]node_modules[\\/](react|react-dom|react-router|react-router-dom|scheduler)[\\/]/],
            ['charts', /[\\/]node_modules[\\/]recharts[\\/]/],
            ['icons', /[\\/]node_modules[\\/]@phosphor-icons[\\/]/],
            ['query', /[\\/]node_modules[\\/](@tanstack[\\/]react-query|zustand)[\\/]/],
          ]
          for (const [name, pattern] of groups) {
            if (pattern.test(id)) return name
          }
          return undefined
        },
      },
    },
  },
})
