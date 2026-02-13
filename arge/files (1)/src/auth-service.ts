import express, { Express } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { sessionMiddleware } from './session-store';
import { initializeDatabase } from './database';
import authRoutes from './routes/auth';

dotenv.config();

const app: Express = express();

// Middleware
app.use(express.json());
app.use(sessionMiddleware); // ← Session middleware

const allowedDomains = process.env.ALLOWED_DOMAINS?.split(',') || [
  'localhost:3000',
  'localhost:3001'
];

app.use(cors({
  origin: allowedDomains,
  credentials: true
}));

// Routes
app.use('/api/auth', authRoutes);

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', sessionId: req.sessionID });
});

const PORT = process.env.PORT || 3000;

async function startServer() {
  try {
    await initializeDatabase();
    app.listen(PORT, () => {
      console.log(`Auth Service ${PORT} portunda çalışıyor (Session: Redis)`);
    });
  } catch (error) {
    console.error('Server başlatma hatası:', error);
    process.exit(1);
  }
}

startServer();