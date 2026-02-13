/**
 * POST /api/auth/login
 */
router.post('/login', verifyDeviceIdMiddleware, async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    const { email, password, redirectUrl } = req.body;

    if (!email || !password) {
      res.status(400).json({ error: 'Email ve şifre gerekli' });
      return;
    }

    const user = await findUserByEmail(email);
    if (!user) {
      res.status(401).json({ error: 'Email veya şifre hatalı' });
      return;
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      res.status(401).json({ error: 'Email veya şifre hatalı' });
      return;
    }

    const accessToken = generateAccessToken(email, user.id);
    const refreshToken = generateRefreshToken(email, user.id);
    const deviceId = req.deviceId!;

    await saveRefreshToken(user.id, refreshToken, deviceId);
    await logSessionHistory(user.id, deviceId, 'LOGIN', req.ip, req.headers['user-agent']);

    res.json({
      success: true,
      accessToken,
      refreshToken,
      deviceId,
      user: { id: user.id, email, name: user.name },
      redirectUrl: redirectUrl ? buildRedirectUrl(redirectUrl, accessToken, refreshToken, deviceId) : null
    });

  } catch (error) {
    console.error('Login hatası:', error);
    res.status(500).json({ error: 'Giriş işlemi başarısız' });
  }
});

/**
 * Redirect URL güvenli şekilde oluştur
 */
function buildRedirectUrl(
  baseUrl: string,
  accessToken: string,
  refreshToken: string,
  deviceId: string
): string {
  const allowedDomains = process.env.ALLOWED_REDIRECT_HOSTS?.split(',') || [];
  
  try {
    const url = new URL(baseUrl);
    
    // Whitelist kontrol (XSS koruması)
    if (!allowedDomains.some(domain => url.hostname.endsWith(domain))) {
      throw new Error('Geçersiz redirect domain');
    }

    // Fragment'e (URL #'den sonra) token ekle
    // Fragment browser tarafından server'a gönderilmez (güvenli)
    url.hash = `token=${encodeURIComponent(accessToken)}&refresh=${encodeURIComponent(refreshToken)}&device=${deviceId}`;
    
    return url.toString();
  } catch (error) {
    console.error('Redirect URL hatası:', error);
    return null as any;
  }
}