import { Router, Response } from 'express';
import { z } from 'zod';
import { authenticate, requireRole, AuthenticatedRequest } from '../middlewares/authMiddleware';
import { handleUpload } from '../middlewares/uploadMiddleware';
import { DocumentService } from '../services/documentService';

export const documentRouter = Router();

// All document routes require authentication
documentRouter.use(authenticate);

const uploadMetadataSchema = z.object({
  title: z.string().min(1, 'Title is required').max(200),
  description: z.string().optional(),
  category: z.string().min(1, 'Category is required'),
  classification: z.enum(['Public', 'Internal', 'Restricted', 'Confidential']).optional()
});

/**
 * POST /api/documents
 * Securely uploads a document. Allowed for 'owner' and 'admin' roles.
 */
documentRouter.post('/', requireRole('owner', 'admin'), handleUpload, (req: AuthenticatedRequest, res: Response) => {
  try {
    if (!req.file) {
      res.status(400).json({ error: 'No file uploaded. Multipart field "file" is required', code: 'FILE_MISSING' });
      return;
    }

    const parsed = uploadMetadataSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'Validation failed', details: parsed.error.issues });
      return;
    }

    const ipAddress = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';
    const userAgent = req.headers['user-agent'] || 'client';

    const document = DocumentService.uploadDocument(
      req.user!,
      {
        originalname: req.file.originalname,
        buffer: req.file.buffer,
        size: req.file.size
      },
      parsed.data,
      ipAddress,
      userAgent
    );

    res.status(201).json({ document });
  } catch (err: any) {
    const status = err.statusCode || 400;
    res.status(status).json({ error: err.message, code: 'UPLOAD_FAILED' });
  }
});

/**
 * GET /api/documents
 * Searches and lists documents accessible to the requester.
 * Query params: q, category, ownerId, fromDate, toDate, limit, offset
 */
documentRouter.get('/', (req: AuthenticatedRequest, res: Response) => {
  try {
    const { q, category, ownerId, fromDate, toDate, limit, offset } = req.query;

    const result = DocumentService.searchDocuments(req.user!, {
      query: typeof q === 'string' ? q : undefined,
      category: typeof category === 'string' ? category : undefined,
      ownerId: typeof ownerId === 'string' ? ownerId : undefined,
      fromDate: typeof fromDate === 'string' ? fromDate : undefined,
      toDate: typeof toDate === 'string' ? toDate : undefined,
      limit: limit ? parseInt(limit as string, 10) : 50,
      offset: offset ? parseInt(offset as string, 10) : 0
    });

    res.json(result);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/documents/:id
 * Fetches document metadata. Verifies active permission in real-time.
 */
documentRouter.get('/:id', (req: AuthenticatedRequest, res: Response) => {
  try {
    const ipAddress = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';
    const userAgent = req.headers['user-agent'] || 'client';

    const document = DocumentService.getDocumentById(req.params.id, req.user!, ipAddress, userAgent);
    res.json({ document });
  } catch (err: any) {
    const status = err.statusCode || 500;
    res.status(status).json({ error: err.message, code: status === 403 ? 'FORBIDDEN' : 'NOT_FOUND' });
  }
});

/**
 * GET /api/documents/:id/download
 * Streams file download with strict headers. Real-time permission gate.
 */
documentRouter.get('/:id/download', (req: AuthenticatedRequest, res: Response) => {
  try {
    const ipAddress = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';
    const userAgent = req.headers['user-agent'] || 'client';

    const fileInfo = DocumentService.getFileForDownload(req.params.id, req.user!, ipAddress, userAgent);

    // Apply strict download security headers to prevent browser execution and unauthorized caching
    res.setHeader('Content-Type', fileInfo.mimeType);
    res.setHeader('Content-Disposition', `attachment; filename="${fileInfo.filename}"`);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Security-Policy', "default-src 'none'");
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('ETag', `"${fileInfo.checksum}"`);

    res.sendFile(fileInfo.filePath);
  } catch (err: any) {
    const status = err.statusCode || 500;
    res.status(status).json({ error: err.message, code: status === 403 ? 'FORBIDDEN' : 'DOWNLOAD_FAILED' });
  }
});

/**
 * PUT /api/documents/:id
 * Updates document metadata or uploads a replacement version.
 * Requires 'edit' or 'owner' permission.
 */
documentRouter.put('/:id', handleUpload, (req: AuthenticatedRequest, res: Response) => {
  try {
    const ipAddress = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';
    const userAgent = req.headers['user-agent'] || 'client';

    const updates: any = {};
    if (req.body.title) updates.title = req.body.title;
    if (req.body.description !== undefined) updates.description = req.body.description;
    if (req.body.category) updates.category = req.body.category;
    if (req.body.classification) updates.classification = req.body.classification;

    if (req.file) {
      updates.newFile = {
        originalname: req.file.originalname,
        buffer: req.file.buffer,
        size: req.file.size
      };
    }

    const updatedDoc = DocumentService.updateDocument(req.params.id, req.user!, updates, ipAddress, userAgent);
    res.json({ document: updatedDoc });
  } catch (err: any) {
    const status = err.statusCode || 400;
    res.status(status).json({ error: err.message, code: status === 403 ? 'FORBIDDEN' : 'UPDATE_FAILED' });
  }
});

/**
 * DELETE /api/documents/:id
 * Deletes document. Requires 'owner' permission.
 */
documentRouter.delete('/:id', (req: AuthenticatedRequest, res: Response) => {
  try {
    const ipAddress = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';
    const userAgent = req.headers['user-agent'] || 'client';

    DocumentService.deleteDocument(req.params.id, req.user!, ipAddress, userAgent);
    res.json({ success: true, message: 'Document securely deleted' });
  } catch (err: any) {
    const status = err.statusCode || 400;
    res.status(status).json({ error: err.message, code: status === 403 ? 'FORBIDDEN' : 'DELETE_FAILED' });
  }
});
