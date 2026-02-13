import express, { Express } from 'express';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import dotenv from 'dotenv';
import { initializeDatabase } from './database';
import authRoutes from './routes/auth';

dotenv.config();

const app: Express = express();

// Middleware
app.use(express.json());
app.use(cookieParser()); // ← Cookie parser ekle

const allowedDomains = process.env.ALLOWED_DOMAINS?.split(',') || [
  'localhost:3000',
  'localhost:3001'
];

app.use(cors({
  origin: allowedDomains,
  credentials: true // ← Önemli: cookies'i gönder
}));

// Routes
app.use('/api/auth', authRoutes);

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Server başlat
const PORT = process.env.PORT || 3000;

async function startServer() {
  try {
    await initializeDatabase();

    app.listen(PORT, () => {
      console.log(`Auth Service ${PORT} portunda çalışıyor`);
    });
  } catch (error) {
    console.error('Server başlatma hatası:', error);
    process.exit(1);
  }
}

startServer();