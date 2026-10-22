
import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { FileService } from './fileService';
import { supabase, SUPABASE_STORAGE_BUCKET } from '../supabase';

export interface SupabaseStoredFileMetadata {
  storagePath: string;
  originalFilename: string;
  fileSizeBytes: number;
  mimeType: string;
  checksumSha256: string;
}

export class SupabaseFileService {
  /**
   * Validate and upload a file to the private Supabase Storage bucket.
   */
  public static async saveToVault(
    buffer: Buffer,
    sanitizedFilename: string,
    mimeType: string
  ): Promise<SupabaseStoredFileMetadata> {
    // Reuse the existing application's upload validation.
    // Reuse the existing application's upload validation.

const validation = FileService.validateUpload({
  originalname: sanitizedFilename,
  buffer,
  size: buffer.length,
  mimetype: mimeType
});

if (!validation.valid) {
  throw new Error(validation.error || 'File validation failed');
}

const verifiedFilename = validation.sanitizedFilename;
const verifiedMime = validation.verifiedMime;

if (!verifiedFilename || !verifiedMime) {
  throw new Error('File validation did not return verified file details');
}
    const storageUuid = uuidv4();
    const checksumSha256 = crypto
      .createHash('sha256')
      .update(buffer)
      .digest('hex');

        const { error } = await supabase.storage
      .from(SUPABASE_STORAGE_BUCKET)
      .upload(storageUuid, buffer, {
        contentType: verifiedMime,
        upsert: false
      });

    if (error) {
      throw new Error(`Supabase upload failed: ${error.message}`);
    }

    return {
      storagePath: storageUuid,
            originalFilename: verifiedFilename,
      fileSizeBytes: buffer.length,
            mimeType: verifiedMime,
      checksumSha256
    };
  }

  /**
   * Download file bytes from private Supabase Storage.
   * Never exposes a public URL or signed URL.
   */
  public static async getFileBuffer(storagePath: string): Promise<Buffer> {
    const storageKey = this.validateStoragePath(storagePath);

    const { data, error } = await supabase.storage
      .from(SUPABASE_STORAGE_BUCKET)
      .download(storageKey);

    if (error || !data) {
      throw new Error(
        `Supabase download failed: ${error?.message ?? 'File not found'}`
      );
    }

    return Buffer.from(await data.arrayBuffer());
  }

  /**
   * Delete a file from private Supabase Storage.
   */
  public static async deleteFromVault(storagePath: string): Promise<void> {
    const storageKey = this.validateStoragePath(storagePath);

    const { error } = await supabase.storage
      .from(SUPABASE_STORAGE_BUCKET)
      .remove([storageKey]);

    if (error) {
      throw new Error(`Supabase delete failed: ${error.message}`);
    }
  }

  /**
   * Prevent storage keys from containing paths or traversal segments.
   */
  private static validateStoragePath(storagePath: string): string {
    if (
      typeof storagePath !== 'string' ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
        storagePath
      )
    ) {
      throw new Error('Invalid vault storage identifier');
    }

    return storagePath;
  }
}
