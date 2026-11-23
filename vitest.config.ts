import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  resolve: {
    alias: { '#transport': fileURLToPath(new URL('./src/internal/http-fetch.node.ts', import.meta.url)) },
  },
  test: {
    coverage: {
      provider: 'v8',
    },
  },
});
