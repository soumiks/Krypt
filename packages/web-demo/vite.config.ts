import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  base: '/Krypt/', // for GitHub Pages
  build: {
    target: 'esnext' // for top-level await and modern WASM support if needed
  }
});
