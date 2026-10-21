import fs from 'node:fs';
import path from 'node:path';
import { postgresPool } from './postgres';

async function migrate(): Promise<void> {
  const migrationPath = path.join(
    __dirname,
    'migrations',
    '001_initial_schema.sql',
  );

  if (!fs.existsSync(migrationPath)) {
    throw new Error(
      `Migration file not found: ${migrationPath}`,
    );
  }

  const sql = fs.readFileSync(migrationPath, 'utf8');
  const client = await postgresPool.connect();

  try {
    await client.query('BEGIN');
    await client.query(sql);
    await client.query('COMMIT');

    console.log('PostgreSQL schema migration completed.');
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
    await postgresPool.end();
  }
}

migrate().catch((error: unknown) => {
  console.error('PostgreSQL migration failed:', error);
  process.exitCode = 1;
});