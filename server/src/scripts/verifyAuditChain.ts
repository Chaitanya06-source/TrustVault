import { PgAuditService } from '../services/auditService.pg';
import { postgresPool } from '../db/postgres';

async function main(): Promise<void> {
  console.log('--- TrustVault PostgreSQL Audit Ledger Verifier ---');

  try {
    const result = await PgAuditService.verifyChainIntegrity();

    if (result.valid) {
      console.log('AUDIT CHAIN INTEGRITY: VERIFIED');
      console.log(`   Total Records:   ${result.totalRecords}`);
      console.log(`   Genesis Link:    ${result.totalRecords > 0 ? 'Verified' : 'N/A (empty ledger)'}`);
      console.log(`   Latest Hash:     ${result.latestHash || 'N/A'}`);
      console.log(`   Message:         ${result.message}`);
      console.log(`   Verified At:     ${result.verifiedAt || new Date().toISOString()}`);

      if (result.totalRecords === 0) {
        console.warn('WARNING: No audit records exist in the connected PostgreSQL database.');
        process.exitCode = 2;
      }
    } else {
      console.error('SECURITY ALERT: AUDIT LEDGER INTEGRITY FAILURE');
      console.error(`   Total Records:   ${result.totalRecords}`);
      console.error(`   Broken At:       ${result.brokenAt ?? 'Unknown'}`);
      console.error(`   Failure Reason:  ${result.message}`);
      process.exitCode = 1;
    }
  } catch (error) {
    console.error('Audit verification failed:', error);
    process.exitCode = 1;
  } finally {
    await postgresPool.end();
  }
}

void main();
