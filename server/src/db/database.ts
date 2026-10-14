import { DatabaseSync } from 'node:sqlite';
import { CONFIG } from '../config';

let dbInstance: DatabaseSync | null = null;

export function getDatabase(): DatabaseSync {
  if (!dbInstance) {
    dbInstance = new DatabaseSync(CONFIG.DB_PATH);
    // Enable WAL mode and foreign keys for high concurrency and referential integrity
    dbInstance.exec('PRAGMA foreign_keys = ON;');
    dbInstance.exec('PRAGMA journal_mode = WAL;');
    initSchema(dbInstance);
  }
  return dbInstance;
}

export function initSchema(db: DatabaseSync): void {
  // Users table
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('admin', 'owner', 'viewer')),
      is_active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL
    );
  `);

  // Documents table
  db.exec(`
    CREATE TABLE IF NOT EXISTS documents (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT,
      category TEXT NOT NULL,
      classification TEXT NOT NULL DEFAULT 'Confidential',
      owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      storage_path TEXT NOT NULL,
      original_filename TEXT NOT NULL,
      file_size_bytes INTEGER NOT NULL,
      mime_type TEXT NOT NULL,
      checksum_sha256 TEXT NOT NULL,
      version INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_docs_owner ON documents(owner_id);
    CREATE INDEX IF NOT EXISTS idx_docs_category ON documents(category);
    CREATE INDEX IF NOT EXISTS idx_docs_title ON documents(title);
  `);

  // Document Permissions table
  db.exec(`
    CREATE TABLE IF NOT EXISTS document_permissions (
      id TEXT PRIMARY KEY,
      document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      permission_level TEXT NOT NULL CHECK(permission_level IN ('view', 'edit')),
      granted_by TEXT NOT NULL REFERENCES users(id),
      granted_at TEXT NOT NULL,
      UNIQUE(document_id, user_id)
    );
    CREATE INDEX IF NOT EXISTS idx_perm_doc_user ON document_permissions(document_id, user_id);
    CREATE INDEX IF NOT EXISTS idx_perm_user ON document_permissions(user_id);
  `);

  // Tamper-Evident Audit Logs table
  db.exec(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY,
      sequence_number INTEGER NOT NULL UNIQUE,
      timestamp TEXT NOT NULL,
      actor_id TEXT NOT NULL,
      actor_email TEXT NOT NULL,
      actor_role TEXT NOT NULL,
      action TEXT NOT NULL,
      target_type TEXT NOT NULL,
      target_id TEXT,
      target_name TEXT,
      status TEXT NOT NULL CHECK(status IN ('SUCCESS', 'DENIED', 'TAMPER_ALERT', 'ERROR')),
      details_json TEXT,
      ip_address TEXT NOT NULL,
      user_agent TEXT NOT NULL,
      prev_hash TEXT NOT NULL,
      record_hash TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_audit_seq ON audit_logs(sequence_number);
    CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_logs(actor_id);
    CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_logs(target_id);
    CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action);
    CREATE INDEX IF NOT EXISTS idx_audit_status ON audit_logs(status);
  `);

  // AI Access Advisory suggestions table (records AI suggestions, rationale, and owner confirmation)
  db.exec(`
    CREATE TABLE IF NOT EXISTS ai_advisory_logs (
      id TEXT PRIMARY KEY,
      document_id TEXT REFERENCES documents(id) ON DELETE CASCADE,
      document_title TEXT NOT NULL,
      suggested_classification TEXT NOT NULL,
      suggested_recipients_json TEXT NOT NULL,
      security_rationale TEXT NOT NULL,
      actor_id TEXT NOT NULL REFERENCES users(id),
      status TEXT NOT NULL CHECK(status IN ('PENDING', 'ACCEPTED', 'REJECTED', 'MODIFIED')),
      confirmed_recipients_json TEXT,
      created_at TEXT NOT NULL,
      decided_at TEXT
    );
  `);
}

// For unit testing with clean in-memory or temporary database
export function resetDatabase(customDb?: DatabaseSync): void {
  if (customDb) {
    dbInstance = customDb;
  }
}
