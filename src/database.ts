import mysql, { Pool, RowDataPacket } from 'mysql2/promise';
import dotenv from 'dotenv';

dotenv.config();

let pool: Pool | null = null;

/**
 * Veritabanı bağlantı pool'unu başlat
 */
export async function initializeDatabase(): Promise<Pool> {
  if (pool) {
    return pool;
  }

  pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME || 'auth_service',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
  });

  console.log('Veritabanı bağlantısı başarılı');
  return pool;
}

/**
 * Veritabanı pool'unu al
 */
export function getDatabase(): Pool {
  if (!pool) {
    throw new Error('Veritabanı başlatılmadı');
  }
  return pool;
}

/**
 * Veritabanı bağlantısını kapat
 */
export async function closeDatabase(): Promise<void> {
  if (pool) {
    await pool.end();
    pool = null;
    console.log('Veritabanı bağlantısı kapatıldı');
  }
}

// ============ USER OPERATIONS ============

/**
 * Email'e göre kullanıcı bul
 */
export async function findUserByEmail(email: string): Promise<any | null> {
  const db = getDatabase();
  const [users] = await db.query<RowDataPacket[]>(
    'SELECT id, password, name FROM users WHERE email = ?',
    [email]
  );

  return users.length > 0 ? users[0] : null;
}

/**
 * ID'ye göre kullanıcı bul
 */
export async function findUserById(id: number): Promise<any | null> {
  const db = getDatabase();
  const [users] = await db.query<RowDataPacket[]>(
    'SELECT id, email, name FROM users WHERE id = ?',
    [id]
  );

  return users.length > 0 ? users[0] : null;
}

/**
 * Yeni kullanıcı oluştur
 */
export async function createUser(email: string, hashedPassword: string, name: string): Promise<number> {
  const db = getDatabase();
  
  // Email zaten var mı kontrol et
  const existingUser = await findUserByEmail(email);
  if (existingUser) {
    throw new Error('Email zaten kullanımda');
  }

  const [result] = await db.query(
    'INSERT INTO users (email, password, name, created_at) VALUES (?, ?, ?, NOW())',
    [email, hashedPassword, name]
  );

  return (result as any).insertId;
}

// ============ REFRESH TOKEN OPERATIONS ============

/**
 * Refresh token'ı veritabanına kaydet
 */
export async function saveRefreshToken(
  userId: number,
  token: string,
  deviceId: string
): Promise<void> {
  const db = getDatabase();
  
  await db.query(
    'INSERT INTO refresh_tokens (user_id, token, device_id, expires_at) VALUES (?, ?, ?, DATE_ADD(NOW(), INTERVAL 7 DAY))',
    [userId, token, deviceId]
  );
}

/**
 * Refresh token'ı bul ve doğrula
 */
export async function findRefreshToken(token: string, deviceId: string): Promise<any | null> {
  const db = getDatabase();
  
  const [tokens] = await db.query<RowDataPacket[]>(
    'SELECT user_id, token FROM refresh_tokens WHERE token = ? AND device_id = ? AND expires_at > NOW()',
    [token, deviceId]
  );

  return tokens.length > 0 ? tokens[0] : null;
}

/**
 * Refresh token'ı sil
 */
export async function deleteRefreshToken(token: string, deviceId: string): Promise<void> {
  const db = getDatabase();
  
  await db.query(
    'DELETE FROM refresh_tokens WHERE token = ? AND device_id = ?',
    [token, deviceId]
  );
}

/**
 * Kullanıcıya ait tüm refresh token'ları sil (isteğe bağlı)
 */
export async function deleteAllUserRefreshTokens(userId: number): Promise<void> {
  const db = getDatabase();
  
  await db.query(
    'DELETE FROM refresh_tokens WHERE user_id = ?',
    [userId]
  );
}

// ============ SESSION HISTORY OPERATIONS ============

/**
 * Oturum geçmişine kayıt ekle
 */
export async function logSessionHistory(
  userId: number,
  deviceId: string,
  action: string,
  ipAddress?: string,
  userAgent?: string
): Promise<void> {
  const db = getDatabase();
  
  await db.query(
    'INSERT INTO session_history (user_id, device_id, action, ip_address, user_agent, created_at) VALUES (?, ?, ?, ?, ?, NOW())',
    [userId, deviceId, action, ipAddress || null, userAgent || null]
  );
}

// Periyodik pool durumu kontrol et
setInterval(() => {
  const stats = (pool as any)._allConnections?.length || 0;
  const free = (pool as any)._freeConnections?.length || 0;
  console.log(`Pool: ${free}/${stats} bağlantı serbest`);
}, 30000); // Her 30 saniyede bir