import { createClient } from 'redis';
import session from 'express-session';
import RedisStore from 'connect-redis';

// Redis client oluştur
export const redisClient = createClient({
  host: process.env.REDIS_HOST || 'localhost',
  port: parseInt(process.env.REDIS_PORT || '6379'),
  db: parseInt(process.env.REDIS_DB || '0')
});

redisClient.connect().catch(err => {
  console.error('Redis bağlantı hatası:', err);
});

// Session store
const store = new RedisStore({ client: redisClient });

export const sessionMiddleware = session({
  store,
  secret: process.env.SESSION_SECRET || 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production', // HTTPS
    httpOnly: true,
    sameSite: 'lax',
    domain: process.env.SESSION_COOKIE_DOMAIN || 'localhost', // ← KEY!
    maxAge: 7 * 24 * 60 * 60 * 1000 // 7 gün
  }
});