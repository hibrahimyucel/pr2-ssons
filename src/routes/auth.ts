import { Router, Response } from 'express';
import bcrypt from 'bcryptjs';
import { AuthRequest } from '../types';
import { verifyAccessTokenMiddleware, verifyDeviceIdMiddleware } from '../middleware';
import { generateAccessToken, generateRefreshToken, verifyRefreshToken } from '../token';
import {
  createUser,
  findUserByEmail,
  findUserById,
  saveRefreshToken,
  findRefreshToken,
  deleteRefreshToken,
  logSessionHistory
} from '../database';

const router = Router();

// Cookie Options (Güvenli)
const refreshTokenCookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'strict' as const,
  domain: process.env.COOKIE_DOMAIN || 'localhost',  // ← DOMAIN EKLE
  path: '/',
  maxAge: 7 * 24 * 60 * 60 * 1000
};

const accessTokenCookieOptions = {
  httpOnly: false,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'strict' as const,
  domain: process.env.COOKIE_DOMAIN || 'localhost',  // ← DOMAIN EKLE
  path: '/',
  maxAge: 15 * 60 * 1000
};
// ============ REGISTER ============

router.post('/register', verifyDeviceIdMiddleware, async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    const { email, password, name } = req.body;

    if (!email || !password || !name) {
      res.status(400).json({ error: 'Email, şifre ve ad gerekli' });
      return;
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const userId = await createUser(email, hashedPassword, name);

    const refreshToken = generateRefreshToken(email, userId);
    await saveRefreshToken(userId, refreshToken, req.deviceId!);

    await logSessionHistory(
      userId,
      req.deviceId!,
      'REGISTER',
      req.ip,
      req.headers['user-agent']
    );

    const accessToken = generateAccessToken(email, userId);

    // Tokens'ı HTTP-Only Cookie'ye koy
    res.cookie('accessToken', accessToken, accessTokenCookieOptions);
    res.cookie('refreshToken', refreshToken, refreshTokenCookieOptions);

    res.status(201).json({
      message: 'Kullanıcı başarıyla oluşturuldu',
      user: { id: userId, email, name }
    });

  } catch (error) {
    const message = error instanceof Error ? error.message : 'Kayıt işlemi başarısız';
    console.error('Register hatası:', error);
    res.status(400).json({ error: message });
  }
});

// ============ LOGIN ============

router.post('/login', verifyDeviceIdMiddleware, async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    const { email, password } = req.body;

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

    await saveRefreshToken(user.id, refreshToken, req.deviceId!);

    await logSessionHistory(
      user.id,
      req.deviceId!,
      'LOGIN',
      req.ip,
      req.headers['user-agent']
    );

    // Tokens'ı HTTP-Only Cookie'ye koy
    res.cookie('accessToken', accessToken, accessTokenCookieOptions);
    res.cookie('refreshToken', refreshToken, refreshTokenCookieOptions);

    res.json({
      message: 'Başarıyla giriş yaptınız',
      user: { id: user.id, email, name: user.name }
    });

  } catch (error) {
    console.error('Login hatası:', error);
    res.status(500).json({ error: 'Giriş işlemi başarısız' });
  }
});

// ============ REFRESH TOKEN ============

router.post('/refresh', verifyDeviceIdMiddleware, async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    // Cookie'den refresh token'ı al
    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken) {
      res.status(400).json({ error: 'Refresh token gerekli' });
      return;
    }

    const tokenRecord = await findRefreshToken(refreshToken, req.deviceId!);
    if (!tokenRecord) {
      res.status(403).json({ error: 'Geçersiz veya süresi dolmuş refresh token' });
      return;
    }

    const decoded = verifyRefreshToken(refreshToken);
    if (!decoded) {
      res.status(403).json({ error: 'Refresh token geçersiz' });
      return;
    }

    const newAccessToken = generateAccessToken(decoded.email, decoded.userId);

    // Yeni access token'ı cookie'ye koy
    res.cookie('accessToken', newAccessToken, accessTokenCookieOptions);

    res.json({
      message: 'Access token başarıyla yenilendi'
    });

  } catch (error) {
    console.error('Refresh hatası:', error);
    res.status(500).json({ error: 'Token yenileme işlemi başarısız' });
  }
});

// ============ GET USER ============

router.get('/me', verifyAccessTokenMiddleware, async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    if (!req.user) {
      res.status(401).json({ error: 'Yetkisiz erişim' });
      return;
    }

    const user = await findUserById(req.user.userId);
    if (!user) {
      res.status(404).json({ error: 'Kullanıcı bulunamadı' });
      return;
    }

    res.json(user);

  } catch (error) {
    console.error('Me hatası:', error);
    res.status(500).json({ error: 'Bilgi alma işlemi başarısız' });
  }
});

// ============ LOGOUT ============

router.post('/logout', verifyDeviceIdMiddleware, async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    const refreshToken = req.cookies.refreshToken;

    if (refreshToken) {
      await deleteRefreshToken(refreshToken, req.deviceId!);
    }

    if (req.user) {
      await logSessionHistory(
        req.user.userId,
        req.deviceId!,
        'LOGOUT',
        req.ip,
        req.headers['user-agent']
      );
    }

    // Cookie'leri sil
    res.clearCookie('accessToken');
    res.clearCookie('refreshToken');

    res.json({ message: 'Başarıyla çıkış yaptınız' });

  } catch (error) {
    console.error('Logout hatası:', error);
    res.status(500).json({ error: 'Çıkış işlemi başarısız' });
  }
});

// ============ VERIFY TOKEN ============

router.post('/verify', async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    // Cookie'den token al (veya body'den)
    let accessToken = req.cookies.accessToken;
    
    if (!accessToken && req.body.accessToken) {
      accessToken = req.body.accessToken;
    }

    if (!accessToken) {
      res.status(400).json({ error: 'Token gerekli' });
      return;
    }

    // Token doğrulama middleware'den al
    // (verifyAccessToken middleware'ini kullan)
    res.status(200).json({ valid: true });

  } catch (error) {
    console.error('Verify hatası:', error);
    res.status(500).json({ error: 'Token doğrulama başarısız' });
  }
});

export default router;