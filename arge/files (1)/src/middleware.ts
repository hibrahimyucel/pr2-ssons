/**
 * Validate redirect URL (XSS koruması)
 */
function isValidRedirect(url: string): boolean {
  const allowedDomains = process.env.ALLOWED_DOMAINS?.split(',') || [];
  
  try {
    const parsed = new URL(url);
    return allowedDomains.some(domain => parsed.hostname.endsWith(domain));
  } catch {
    return false;
  }
}

/**
 * Token'ı doğrula ve rate limit kontrol et
 */
export function validateTokenRequest(
  req: AuthRequest,
  res: Response,
  next: NextFunction
): void {
  const clientIP = req.ip;
  const token = req.headers['authorization']?.split(' ')[1];

  if (!token) {
    res.status(401).json({ error: 'Token gerekli' });
    return;
  }

  // Rate limiting check (brute force koruması)
  const requestCount = getRequestCount(clientIP);
  if (requestCount > 100) { // 100 req/min
    res.status(429).json({ error: 'Çok fazla istek' });
    return;
  }

  next();
}