import { app } from './app';
import { CONFIG } from './config';
import { postgresPool } from './db/postgres';

async function startServer() {
  try {
    await postgresPool.query('SELECT 1');

    const server = app.listen(CONFIG.PORT, () => {
      console.log('=======================================================');
      console.log('   TrustVault Zero-Trust Security Core is RUNNING     ');
      console.log(`   Port:       http://localhost:${CONFIG.PORT}`);
      console.log(`   Storage:    ${CONFIG.STORAGE_DIR}`);
      console.log('   Database:   Neon PostgreSQL');
      console.log('=======================================================');
    });

    return server;
  } catch (error) {
    console.error('Failed to connect to PostgreSQL:', error);
    process.exitCode = 1;
  }
}

void startServer();
