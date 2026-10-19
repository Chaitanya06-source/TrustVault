import { app } from './app';
import { CONFIG } from './config';
import { getDatabase } from './db/database';
import { runSeed } from './db/seed';

// Ensure database and schema are initialized
getDatabase();
// Run seed if fresh database
runSeed();

const server = app.listen(CONFIG.PORT, () => {
  console.log(`=======================================================`);
  console.log(`   TrustVault Zero-Trust Security Core is RUNNING     `);
  console.log(`   Port:       http://localhost:${CONFIG.PORT}        `);
  console.log(`   Storage:    ${CONFIG.STORAGE_DIR}                  `);
  console.log(`   Database:   ${CONFIG.DB_PATH}                      `);
  console.log(`=======================================================`);
});

export { server };
