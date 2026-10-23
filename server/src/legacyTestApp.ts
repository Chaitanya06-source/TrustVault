import path from 'path';
import fs from 'fs';
import express, { Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import { authRouter } from './legacyTestRoutes/authRoutes';
import { documentRouter } from './legacyTestRoutes/documentRoutes';
import { permissionRouter } from './legacyTestRoutes/permissionRoutes';
import { auditRouter } from './legacyTestRoutes/auditRoutes';
import { adminRouter } from './legacyTestRoutes/adminRoutes';
import { aiRouter } from './legacyTestRoutes/aiRoutes';


export const app = express();

// Security Headers via Helmet
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:', 'blob:'],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        upgradeInsecureRequests: []
      }
    },
    crossOriginEmbedderPolicy: false
  })
);

// CORS configuration
app.use(
  cors({
    origin: true, // Allow frontend dev server
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
  })
);

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Health check endpoint
app.get('/api/health', (req: Request, res: Response) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    service: 'TrustVault Zero-Trust Security Core'
  });
});

// Mount modular API routers
app.use('/api/auth', authRouter);
app.use('/api/documents', documentRouter);
app.use('/api/documents', permissionRouter);
app.use('/api/audit', auditRouter);
app.use('/api/admin', adminRouter);
app.use('/api/ai', aiRouter);

// Serve built frontend assets if present
const CLIENT_DIST = path.resolve(__dirname, '../../client/dist');
if (fs.existsSync(CLIENT_DIST)) {
  app.use(express.static(CLIENT_DIST));
  app.get('*', (req: Request, res: Response, next: NextFunction) => {
    if (req.path.startsWith('/api')) return next();
    res.sendFile(path.join(CLIENT_DIST, 'index.html'));
  });
}

// Global Error Handler - Prevents internal stack trace leakage
app.use((err: any, req: Request, res: Response, next: NextFunction) => {
  console.error('[TrustVault Error]', err);
  const statusCode = err.statusCode || 500;
  res.status(statusCode).json({
    error: err.message || 'Internal Server Error',
    code: err.code || 'INTERNAL_ERROR'
  });
});
