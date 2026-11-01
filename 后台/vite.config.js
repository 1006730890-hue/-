import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  base: '/admin/',
  plugins: [vue()],
  server: { port: 5174, proxy: { '/api': 'http://127.0.0.1:8018', '/health': 'http://127.0.0.1:8018' } },
  build: { outDir: 'dist' }
})
