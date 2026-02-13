import { Response, NextFunction } from 'express';
import { AuthRequest } from './types';
import { verifyAccessToken } from './token';

/**
 * Access Token doğrulama Middleware'i
 */
export function verifyAccessTokenMiddleware(
  req: AuthRequest,
  res: Response,
  next: NextFunction
): void {
  // Cookie'den token al
  let token = req.cookies.accessToken;

  // Veya Authorization header'dan
  if (!token) {
    const authHeader = req.headers['authorization'];
    token = authHeader && authHeader.split(' ')[1];
  }

  if (!token) {
    res.status(401).json({ error: 'Token gerekli' });
    return;
  }

  const decoded = verifyAccessToken(token);
  if (!decoded) {
    res.status(403).json({ error: 'Token geçersiz veya süresi doldu' });
    return;
  }

  req.user = decoded;
  next();
}

/**
 * Cihaz ID doğrulama Middleware'i
 */
export function verifyDeviceIdMiddleware(
  req: AuthRequest,
  res: Response,
  next: NextFunction
): void {
  const deviceId = req.headers['x-device-id'] as string;
  
  if (!deviceId) {
    res.status(400).json({ error: 'Device ID gerekli' });
    return;
  }

  req.deviceId = deviceId;
  next();
}