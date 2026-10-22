
import { Router, Response } from 'express';
import { z } from 'zod';
import {
  authenticate,
  requireRole,
  AuthenticatedRequest
} from '../middlewares/authMiddleware';
import { handleUpload } from '../middlewares/uploadMiddleware';
import { DocumentService } from '../services/documentService.pg';

export const documentRouter = Router();

documentRouter.use(authenticate);

const uploadMetadataSchema = z.object({
  title: z.string().min(1, 'Title is required').max(200),
  description: z.string().optional(),
  category: z.string().min(1, 'Category is required'),
  classification: z.enum([
    'Public',
    'Internal',
    'Restricted',
    'Confidential'
  ]).optional()
});

function requestDetails(req: AuthenticatedRequest) {
  return {
    ipAddress:
      (req.headers['x-forwarded-for'] as string) ||
      req.socket.remoteAddress ||
      '127.0.0.1',
    userAgent: req.headers['user-agent'] || 'client'
  };
}

function sendError(
  res: Response,
  err: unknown,
  fallbackStatus: number,
  fallbackCode: string
) {
  const error = err as Error & { statusCode?: number };
  const status = error.statusCode || fallbackStatus;

  res.status(status).json({
    error: error.message || 'An unexpected error occurred',
    code:
      status === 403
        ? 'FORBIDDEN'
        : status === 404
          ? 'NOT_FOUND'
          : fallbackCode
  });
}

/**
 * POST /api/documents
 * Upload a document.
 */
documentRouter.post(
  '/',
  requireRole('owner', 'admin'),
  handleUpload,
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      if (!req.file) {
        res.status(400).json({
          error: 'No file uploaded. Multipart field "file" is required',
          code: 'FILE_MISSING'
        });
        return;
      }

      const parsed = uploadMetadataSchema.safeParse(req.body);

      if (!parsed.success) {
        res.status(400).json({
          error: 'Validation failed',
          details: parsed.error.issues
        });
        return;
      }

      const { ipAddress, userAgent } = requestDetails(req);

      const document = await DocumentService.uploadDocument(
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
    } catch (err) {
      sendError(res, err, 400, 'UPLOAD_FAILED');
    }
  }
);

/**
 * GET /api/documents
 * Search accessible documents.
 */
documentRouter.get(
  '/',
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const { q, category, ownerId, fromDate, toDate, limit, offset } =
        req.query;

      const result = await DocumentService.searchDocuments(req.user!, {
        query: typeof q === 'string' ? q : undefined,
        category: typeof category === 'string' ? category : undefined,
        ownerId: typeof ownerId === 'string' ? ownerId : undefined,
        fromDate: typeof fromDate === 'string' ? fromDate : undefined,
        toDate: typeof toDate === 'string' ? toDate : undefined,
        limit: limit ? parseInt(limit as string, 10) : 50,
        offset: offset ? parseInt(offset as string, 10) : 0
      });

      res.json(result);
    } catch (err) {
      sendError(res, err, 500, 'SEARCH_FAILED');
    }
  }
);

/**
 * GET /api/documents/:id
 * Fetch document metadata.
 */
documentRouter.get(
  '/:id',
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const { ipAddress, userAgent } = requestDetails(req);

      const document = await DocumentService.getDocumentById(
        req.params.id,
        req.user!,
        ipAddress,
        userAgent
      );

      res.json({ document });
    } catch (err) {
      sendError(res, err, 500, 'DOCUMENT_FETCH_FAILED');
    }
  }
);

/**
 * GET /api/documents/:id/download
 * Download a document from private Supabase Storage.
 */
documentRouter.get(
  '/:id/download',
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const { ipAddress, userAgent } = requestDetails(req);

      const fileInfo = await DocumentService.getFileForDownload(
        req.params.id,
        req.user!,
        ipAddress,
        userAgent
      );

      res.setHeader('Content-Type', fileInfo.mimeType);
      res.setHeader(
        'Content-Disposition',
        `attachment; filename="${fileInfo.filename.replace(/["\\\r\n]/g, '_')}"`
      );
      res.setHeader('Content-Length', fileInfo.buffer.length);
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('Content-Security-Policy', "default-src 'none'");
      res.setHeader(
        'Cache-Control',
        'no-store, no-cache, must-revalidate, private'
      );
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('ETag', `"${fileInfo.checksum}"`);

      res.send(fileInfo.buffer);
    } catch (err) {
      if (res.headersSent) {
        return;
      }
      sendError(res, err, 500, 'DOWNLOAD_FAILED');
    }
  }
);

/**
 * PUT /api/documents/:id
 * Update metadata or upload a replacement version.
 */
documentRouter.put(
  '/:id',
  handleUpload,
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const { ipAddress, userAgent } = requestDetails(req);

      const updates: {
        title?: string;
        description?: string;
        category?: string;
        classification?: string;
        newFile?: {
          originalname: string;
          buffer: Buffer;
          size: number;
        };
      } = {};

      if (req.body.title !== undefined) {
        updates.title = req.body.title;
      }
      if (req.body.description !== undefined) {
        updates.description = req.body.description;
      }
      if (req.body.category !== undefined) {
        updates.category = req.body.category;
      }
      if (req.body.classification !== undefined) {
        updates.classification = req.body.classification;
      }

      if (req.file) {
        updates.newFile = {
          originalname: req.file.originalname,
          buffer: req.file.buffer,
          size: req.file.size
        };
      }

      const updatedDoc = await DocumentService.updateDocument(
        req.params.id,
        req.user!,
        updates,
        ipAddress,
        userAgent
      );

      res.json({ document: updatedDoc });
    } catch (err) {
      sendError(res, err, 400, 'UPDATE_FAILED');
    }
  }
);

/**
 * DELETE /api/documents/:id
 * Delete a document owned by the requester.
 */
documentRouter.delete(
  '/:id',
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const { ipAddress, userAgent } = requestDetails(req);

      await DocumentService.deleteDocument(
        req.params.id,
        req.user!,
        ipAddress,
        userAgent
      );

      res.json({
        success: true,
        message: 'Document securely deleted'
      });
    } catch (err) {
      sendError(res, err, 400, 'DELETE_FAILED');
    }
  }
);
