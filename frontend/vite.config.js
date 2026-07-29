import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

const apiProxy = process.env.VITE_API_PROXY || 'http://127.0.0.1:4473'

export default defineConfig({
  plugins: [vue()],
  server: { proxy: { '/api': apiProxy, '/health': apiProxy } },
  build: { outDir: 'dist' },
})
