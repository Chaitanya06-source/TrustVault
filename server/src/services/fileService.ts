import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { CONFIG } from '../config';

export interface FileValidationResult {
  valid: boolean;
  error?: string;
  detectedMime?: string;
  sanitizedFilename?: string;
}

export interface StoredFileMetadata {
  storagePath: string; // Internal storage filename (UUID)
  originalFilename: string;
  fileSizeBytes: number;
  mimeType: string;
  checksumSha256: string;
}

export class FileService {
  /**
   * Sanitizes a client-provided filename to prevent path traversal,
   * null byte injection, and illegal filesystem characters.
   */
  public static sanitizeFilename(rawFilename: string): string {
    // 1. Strip all directory paths (both unix / and windows \)
    let clean = path.basename(rawFilename);

    // 2. Remove null bytes and control characters
    clean = clean.replace(/[\x00-\x1f\x7f]/g, '');

    // 3. Remove traversal sequences and dangerous characters
    clean = clean.replace(/(\.\.[\/\\])+/g, '');
    clean = clean.replace(/[^a-zA-Z0-9._\-\s]/g, '_');

    // 4. Fallback if empty or purely dots
    if (!clean || clean.replace(/\./g, '').trim().length === 0) {
      clean = `document_${Date.now()}`;
    }

    // 5. Limit length to 200 chars
    if (clean.length > 200) {
      const ext = path.extname(clean);
      const name = path.basename(clean, ext).substring(0, 190);
      clean = `${name}${ext}`;
    }

    return clean;
  }

  /**
   * Sniffs magic bytes to verify actual file content against claimed extension.
   * Defends against disguised executables (PE/ELF) and script masking.
   */
  public static validateMagicBytes(buffer: Buffer, originalExt: string): { valid: boolean; detectedMime?: string; reason?: string } {
    if (!buffer || buffer.length === 0) {
      return { valid: false, reason: 'File content is empty (0 bytes)' };
    }

    const ext = originalExt.toLowerCase();

    // Check for dangerous binary signatures regardless of extension (e.g. PE 'MZ' or ELF '\x7fELF')
    if (buffer.length >= 2 && buffer[0] === 0x4d && buffer[1] === 0x5a) {
      return { valid: false, reason: 'Security alert: Windows executable (PE/MZ header) rejected' };
    }
    if (buffer.length >= 4 && buffer[0] === 0x7f && buffer[1] === 0x45 && buffer[2] === 0x4c && buffer[3] === 0x46) {
      return { valid: false, reason: 'Security alert: Linux ELF binary header rejected' };
    }

    // Check PDF magic bytes: '%PDF'
    if (ext === '.pdf') {
      const isPdf = buffer.length >= 4 && buffer.toString('utf-8', 0, 4) === '%PDF';
      if (!isPdf) {
        return { valid: false, reason: 'MIME mismatch: file claims .pdf extension but lacks %PDF magic header' };
      }
      return { valid: true, detectedMime: 'application/pdf' };
    }

    // Check PNG magic bytes: \x89PNG\r\n\x1a\n
    if (ext === '.png') {
      const isPng = buffer.length >= 8 &&
        buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4e && buffer[3] === 0x47 &&
        buffer[4] === 0x0d && buffer[5] === 0x0a && buffer[6] === 0x1a && buffer[7] === 0x0a;
      if (!isPng) {
        return { valid: false, reason: 'MIME mismatch: file claims .png extension but lacks PNG magic bytes' };
      }
      return { valid: true, detectedMime: 'image/png' };
    }

    // Check JPEG magic bytes: \xFF\xD8\xFF
    if (ext === '.jpg' || ext === '.jpeg') {
      const isJpg = buffer.length >= 3 && buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff;
      if (!isJpg) {
        return { valid: false, reason: 'MIME mismatch: file claims JPEG extension but lacks JPEG SOI marker' };
      }
      return { valid: true, detectedMime: 'image/jpeg' };
    }

    // Check Office XML (.docx, .xlsx): ZIP container magic 'PK\x03\x04'
    if (ext === '.docx' || ext === '.xlsx') {
      const isZip = buffer.length >= 4 &&
        buffer[0] === 0x50 && buffer[1] === 0x4b && buffer[2] === 0x03 && buffer[3] === 0x04;
      if (!isZip) {
        return { valid: false, reason: `MIME mismatch: file claims ${ext} but lacks OpenXML/ZIP container header` };
      }
      const mime = ext === '.docx'
        ? 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        : 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';
      return { valid: true, detectedMime: mime };
    }

    // Check text/json/csv: must be valid UTF-8 without control characters
    if (ext === '.txt' || ext === '.csv' || ext === '.json') {
      // Check for null bytes or illegal control characters
      for (let i = 0; i < Math.min(buffer.length, 1024); i++) {
        const byte = buffer[i];
        if (byte === 0x00 || (byte < 0x09 && byte !== 0x0a && byte !== 0x0d)) {
          return { valid: false, reason: 'Security alert: binary or null bytes found in plain text document' };
        }
      }

      if (ext === '.json') {
        try {
          JSON.parse(buffer.toString('utf-8'));
          return { valid: true, detectedMime: 'application/json' };
        } catch {
          return { valid: false, reason: 'Invalid JSON syntax' };
        }
      }

      return { valid: true, detectedMime: ext === '.csv' ? 'text/csv' : 'text/plain' };
    }

    return { valid: false, reason: `Disallowed or unverified file extension '${ext}'` };
  }

  /**
   * Comprehensive upload validation pipeline:
   * 1. Size constraint
   * 2. Extension whitelist
   * 3. Filename sanitization
   * 4. Magic-byte verification
   */
  public static validateUpload(file: { originalname: string; buffer: Buffer; size: number; mimetype?: string }): {
    valid: boolean;
    error?: string;
    sanitizedFilename?: string;
    verifiedMime?: string;
  } {
    // 1. Size check
    if (file.size > CONFIG.MAX_FILE_SIZE_BYTES) {
      return { valid: false, error: `File size exceeds the 25MB maximum limit (received ${(file.size / 1024 / 1024).toFixed(1)}MB)` };
    }

    // 2. Sanitization
    const sanitized = this.sanitizeFilename(file.originalname);
    const ext = path.extname(sanitized).toLowerCase();

    // 3. Extension check
    if (!CONFIG.ALLOWED_EXTENSIONS.includes(ext)) {
      return {
        valid: false,
        error: `File type '${ext}' is not permitted. Permitted types: ${CONFIG.ALLOWED_EXTENSIONS.join(', ')}`
      };
    }

    // 4. Magic byte check
    const magicResult = this.validateMagicBytes(file.buffer, ext);
    if (!magicResult.valid) {
      return { valid: false, error: magicResult.reason };
    }

    return {
      valid: true,
      sanitizedFilename: sanitized,
      verifiedMime: magicResult.detectedMime
    };
  }

  /**
   * Safely writes file buffer to isolated storage under an unpredictable UUID filename.
   */
  public static saveToVault(buffer: Buffer, sanitizedFilename: string, mimeType: string): StoredFileMetadata {
    const storageUuid = uuidv4();
    const destinationPath = path.join(CONFIG.STORAGE_DIR, storageUuid);

    // Compute cryptographic SHA-256 checksum of raw file bytes
    const checksumSha256 = crypto.createHash('sha256').update(buffer).digest('hex');

    // Write file to disk
    fs.writeFileSync(destinationPath, buffer);

    return {
      storagePath: storageUuid,
      originalFilename: sanitizedFilename,
      fileSizeBytes: buffer.length,
      mimeType,
      checksumSha256
    };
  }

  /**
   * Retrieves the absolute path to a stored file on disk.
   */
  public static getStorageFilePath(storageUuid: string): string {
    // Defend against path traversal in UUID parameter
    const sanitizedUuid = path.basename(storageUuid);
    const fullPath = path.join(CONFIG.STORAGE_DIR, sanitizedUuid);

    if (!fs.existsSync(fullPath)) {
      throw new Error('Requested vault file does not exist on storage disk');
    }
    return fullPath;
  }

  /**
   * Safely deletes a file from vault storage on disk.
   */
  public static deleteFromVault(storageUuid: string): void {
    const sanitizedUuid = path.basename(storageUuid);
    const fullPath = path.join(CONFIG.STORAGE_DIR, sanitizedUuid);
    if (fs.existsSync(fullPath)) {
      fs.unlinkSync(fullPath);
    }
  }
}
