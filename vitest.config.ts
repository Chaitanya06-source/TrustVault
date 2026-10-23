import { defineConfig } from 'vitest/config';
import { loadEnv } from 'vite';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

// Keep legacy SQLite tests away from the developer's working database.
// A per-run path gives each Vitest process a fresh ledger, preventing stale
// HMAC records and leftovers from failed tests from contaminating later runs.
const testDbPath = path.join(os.tmpdir(), `trustvault-vitest-${process.pid}.db`);
for (const suffix of ['', '-wal', '-shm']) {
  fs.rmSync(`${testDbPath}${suffix}`, { force: true });
}

const env = loadEnv('', process.cwd(), '');
env.DB_PATH = testDbPath;
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
