import multer from 'multer';
import { Request, Response, NextFunction } from 'express';
import { CONFIG } from '../config';

const storage = multer.memoryStorage();

export const uploadMiddleware = multer({
  storage,
  limits: {
    fileSize: CONFIG.MAX_FILE_SIZE_BYTES, // 25 MB
    files: 1
  }
}).single('file');

export function handleUpload(req: Request, res: Response, next: NextFunction): void {
  uploadMiddleware(req, res, (err: any) => {
    if (err instanceof multer.MulterError) {
      if (err.code === 'LIMIT_FILE_SIZE') {
        res.status(400).json({
          error: `File upload rejected: Maximum permitted file size is 25MB`,
          code: 'FILE_TOO_LARGE'
        });
        return;
      }
      res.status(400).json({
        error: `File upload error: ${err.message}`,
        code: 'UPLOAD_ERROR'
      });
      return;
    } else if (err) {
      res.status(400).json({
        error: `Upload processing failure: ${err.message}`,
        code: 'UPLOAD_ERROR'
      });
      return;
    }
    next();
  });
}
