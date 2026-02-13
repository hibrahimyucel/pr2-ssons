import jwt from 'jsonwebtoken';
import { TokenPayload } from './types';

const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET || 'access_secret_key';
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET || 'refresh_secret_key';

// ============ TOKEN GENERATION ============

/**
 * Access Token oluştur (15 dakika)
 */
export function generateAccessToken(email: string, userId: number): string {
  return jwt.sign(
    { email, userId, type: 'access' },
    ACCESS_TOKEN_SECRET,
    { expiresIn: '15m' }
  );
}

/**
 * Refresh Token oluştur (7 gün)
 */
export function generateRefreshToken(email: string, userId: number): string {
  return jwt.sign(
    { email, userId, type: 'refresh' },
    REFRESH_TOKEN_SECRET,
    { expiresIn: '7d' }
  );
}

// ============ TOKEN VERIFICATION ============

/**
 * Access Token doğrula
 */
export function verifyAccessToken(token: string): TokenPayload | null {
  try {
    const decoded = jwt.verify(token, ACCESS_TOKEN_SECRET) as TokenPayload;
    return decoded;
  } catch (error) {
    return null;
  }
}

/**
 * Refresh Token doğrula
 */
export function verifyRefreshToken(token: string): TokenPayload | null {
  try {
    const decoded = jwt.verify(token, REFRESH_TOKEN_SECRET) as TokenPayload;
    return decoded;
  } catch (error) {
    return null;
  }
}

/**
 * Token'ı decode et (doğrulamadan)
 */
export function decodeToken(token: string): TokenPayload | null {
  try {
    const decoded = jwt.decode(token) as TokenPayload | null;
    return decoded;
  } catch (error) {
    return null;
  }
}

/**
 * Token'ın süresi dolmuş mu kontrol et
 */
export function isTokenExpired(token: string): boolean {
  const decoded = decodeToken(token);
  if (!decoded || !decoded.exp) {
    return true;
  }

  const currentTime = Math.floor(Date.now() / 1000);
  return decoded.exp < currentTime;
}