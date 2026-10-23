import { defineConfig } from 'vitest/config';
import { loadEnv } from 'vite';

const env = loadEnv('', process.cwd(), '');
Object.assign(process.env, env);

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    testTimeout: 20000,
    fileParallelism: false,
    include: ['server/tests/**/*.test.ts'],
    env
  }
});