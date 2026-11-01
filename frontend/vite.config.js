import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  server: {
    host: '127.0.0.1',
    port: 5173,
    proxy: {
      '/api': process.env.BANK_API_URL || 'http://127.0.0.1:8018',
      '/health': process.env.BANK_API_URL || 'http://127.0.0.1:8018'
    }
  }
})
