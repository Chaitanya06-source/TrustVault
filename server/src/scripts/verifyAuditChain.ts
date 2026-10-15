import { AuditService } from '../services/auditService';
import { getDatabase } from '../db/database';

console.log('--- TrustVault Cryptographic Audit Ledger Verifier ---');
getDatabase();
const result = AuditService.verifyChainIntegrity();

if (result.valid) {
  console.log('✅ AUDIT CHAIN INTEGRITY: 100% PRISTINE AND VERIFIED');
  console.log(`   Total Blocks:    ${result.totalRecords}`);
  console.log(`   Genesis Hash:    ${result.genesisHash || 'N/A'}`);
  console.log(`   Latest Hash:     ${result.latestHash || 'N/A'}`);
  console.log(`   Verified At:     ${result.verifiedAt}`);
  process.exit(0);
} else {
  console.error('❌ SECURITY ALERT: AUDIT LEDGER TAMPERING DETECTED!');
  console.error(`   Broken at Block Index: ${result.brokenAtIndex}`);
  console.error(`   Record ID:             ${result.brokenRecordId}`);
  console.error(`   Failure Reason:        ${result.failureReason}`);
  console.error(`   Verified At:           ${result.verifiedAt}`);
  process.exit(1);
}
