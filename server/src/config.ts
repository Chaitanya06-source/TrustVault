import path from 'path';
import fs from 'fs';

// Root directory anchors
export const ROOT_DIR = path.resolve(__dirname, '../../');
export const DATA_DIR = path.join(ROOT_DIR, 'data');
export const STORAGE_DIR = path.join(ROOT_DIR, 'storage', 'files');

// Ensure essential directories exist
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}
if (!fs.existsSync(STORAGE_DIR)) {
  fs.mkdirSync(STORAGE_DIR, { recursive: true });
}

export const CONFIG = {
  PORT: process.env.PORT ? parseInt(process.env.PORT, 10) : 4000,
  NODE_ENV: process.env.NODE_ENV || 'development',
  JWT_SECRET: process.env.JWT_SECRET || 'trustvault-super-secure-production-grade-key-2026',
  JWT_EXPIRES_IN: '8h',
  // Master HMAC salt used to bind tamper-evident audit records
  AUDIT_HMAC_SECRET: process.env.AUDIT_HMAC_SECRET || 'trustvault-tamper-evident-merkle-salt-9872164',
  DB_PATH: process.env.DB_PATH || path.join(DATA_DIR, 'trustvault.db'),
  STORAGE_DIR,
  MAX_FILE_SIZE_BYTES: 25 * 1024 * 1024, // 25 MB limit
  // Whitelisted MIME types
  ALLOWED_MIME_TYPES: [
    'application/pdf',
    'text/plain',
    'text/csv',
    'application/json',
    'image/png',
    'image/jpeg',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document', // .docx
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', // .xlsx
  ],
  // Whitelisted file extensions
  ALLOWED_EXTENSIONS: ['.pdf', '.txt', '.csv', '.json', '.png', '.jpg', '.jpeg', '.docx', '.xlsx']
};
