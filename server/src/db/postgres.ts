import { Pool, QueryResultRow } from 'pg';

const connectionString = process.env.DATABASE_URL;

if (!connectionString) {
  throw new Error(
    'DATABASE_URL is required to connect to PostgreSQL.'
  );
}

export const postgresPool = new Pool({
  connectionString,
  ssl: process.env.NODE_ENV === 'production'
    ? { rejectUnauthorized: false }
    : undefined,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
});

postgresPool.on('error', (error) => {
  console.error('Unexpected PostgreSQL pool error:', error.message);
});

export async function postgresQuery<
  T extends QueryResultRow = QueryResultRow
>(
  sql: string,
  params: unknown[] = [],
) {
  return postgresPool.query<T>(sql, params);
}