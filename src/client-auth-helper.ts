interface AuthResponse {
  success: boolean;
  error?: string;
  user?: any;
  accessToken?: string;
  message?: string;
}

class AuthHelper {
  private authServiceUrl: string;
  private deviceIdKey = 'deviceId';
  private deviceId: string;

  constructor(authServiceUrl: string = 'http://localhost:3000') {
    this.authServiceUrl = authServiceUrl;
    this.deviceId = this.getOrCreateDeviceId();
  }

  /**
   * Cihaz ID'si oluştur veya mevcut olanı al
   */
  private getOrCreateDeviceId(): string {
    let deviceId = localStorage.getItem(this.deviceIdKey);
    if (!deviceId) {
      deviceId = this.generateDeviceId();
      localStorage.setItem(this.deviceIdKey, deviceId);
    }
    return deviceId;
  }

  /**
   * Unique cihaz ID'si oluştur
   */
  private generateDeviceId(): string {
    return 'device_' + Math.random().toString(36).substr(2, 9) + '_' + Date.now();
  }

  /**
   * Kayıt yap
   */
  async register(email: string, password: string, name: string): Promise<AuthResponse> {
    try {
      const response = await fetch(`${this.authServiceUrl}/api/auth/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Device-ID': this.deviceId
        },
        credentials: 'include', // ← Cookie'leri al
        body: JSON.stringify({ email, password, name })
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Kayıt başarısız');
      }

      // Access token response'da gelir, ama cookie'de de var
      // localStorage'a koyabiliriz (optional, cookie'den de alabilir)
      if (data.accessToken) {
        sessionStorage.setItem('accessToken', data.accessToken); // sessionStorage tercih (browser kapatınca silinir)
      }

      return { success: true, user: data.user };

    } catch (error) {
      const message = error instanceof Error ? error.message : 'Kayıt başarısız';
      console.error('Register hatası:', error);
      return { success: false, error: message };
    }
  }

  /**
   * Giriş yap
   */
  async login(email: string, password: string): Promise<AuthResponse> {
    try {
      const response = await fetch(`${this.authServiceUrl}/api/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Device-ID': this.deviceId
        },
        credentials: 'include', // ← Cookie'leri al
        body: JSON.stringify({ email, password })
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Giriş başarısız');
      }

      // Access token'ı sessionStorage'a kaydet (optional)
      if (data.accessToken) {
        sessionStorage.setItem('accessToken', data.accessToken);
      }

      return { success: true, user: data.user };

    } catch (error) {
      const message = error instanceof Error ? error.message : 'Giriş başarısız';
      console.error('Login hatası:', error);
      return { success: false, error: message };
    }
  }

  /**
   * Oturum bilgisini al
   */
  async getUser(): Promise<any | null> {
    try {
      const response = await fetch(`${this.authServiceUrl}/api/auth/me`, {
        credentials: 'include' // ← Cookie'leri otomatik gönder
      });

      if (response.status === 401) {
        // Token süresi dolmuş, yenile
        const refreshed = await this.refreshAccessToken();
        if (refreshed) {
          return this.getUser(); // Tekrar dene
        }
        return null;
      }

      if (!response.ok) {
        throw new Error('Kullanıcı bilgisi alınamadı');
      }

      return await response.json();

    } catch (error) {
      console.error('GetUser hatası:', error);
      return null;
    }
  }

  /**
   * Access Token'ı yenile (Refresh token HTTP-Only cookie'den otomatik alınır)
   */
  async refreshAccessToken(): Promise<boolean> {
    try {
      const response = await fetch(`${this.authServiceUrl}/api/auth/refresh`, {
        method: 'POST',
        headers: {
          'X-Device-ID': this.deviceId
        },
        credentials: 'include' // ← HTTP-Only refresh token otomatik gönderilir
      });

      const data: any = await response.json();

      if (!response.ok) {
        return false;
      }

      // Yeni access token'ı sessionStorage'a kaydet
      if (data.accessToken) {
        sessionStorage.setItem('accessToken', data.accessToken);
      }

      return true;

    } catch (error) {
      console.error('Refresh hatası:', error);
      return false;
    }
  }

  /**
   * Çıkış yap
   */
  async logout(): Promise<AuthResponse> {
    try {
      const response = await fetch(`${this.authServiceUrl}/api/auth/logout`, {
        method: 'POST',
        headers: {
          'X-Device-ID': this.deviceId
        },
        credentials: 'include' // ← HTTP-Only refresh token cookie'den silinecek
      });

      const data = await response.json();

      // localStorage ve sessionStorage'ı temizle
      sessionStorage.removeItem('accessToken');

      return { 
        success: response.ok, 
        message: data.message,
        error: !response.ok ? data.error : undefined
      };

    } catch (error) {
      console.error('Logout hatası:', error);
      sessionStorage.removeItem('accessToken');
      const message = error instanceof Error ? error.message : 'Çıkış başarısız';
      return { success: false, error: message };
    }
  }

  /**
   * Access Token'ı al (Cookie'den veya sessionStorage'dan)
   */
  getAccessToken(): string | null {
    // Önce sessionStorage'ı kontrol et
    let token = sessionStorage.getItem('accessToken');
    if (token) return token;

    // Yoksa cookie'den al (getCookie fonksiyonu aşağıda)
    return this.getCookie('accessToken');
  }

  /**
   * Cookie'den değer al
   */
  private getCookie(name: string): string | null {
    const nameEQ = name + '=';
    const cookies = document.cookie.split(';');
    
    for (let i = 0; i < cookies.length; i++) {
      let cookie = cookies[i].trim();
      if (cookie.indexOf(nameEQ) === 0) {
        return decodeURIComponent(cookie.substring(nameEQ.length));
      }
    }
    
    return null;
  }

  /**
   * Authorized API call (Authorization header ile)
   */
  async authenticatedFetch(url: string, options: RequestInit = {}): Promise<Response> {
    let accessToken = this.getAccessToken();

    if (!accessToken) {
      throw new Error('Token bulunamadı, lütfen giriş yapın');
    }

    const headers = {
      ...options.headers,
      'Authorization': `Bearer ${accessToken}`
    };

    let response = await fetch(url, { ...options, headers, credentials: 'include' });

    // 401 ise token yenile ve tekrar dene
    if (response.status === 401) {
      const refreshed = await this.refreshAccessToken();
      if (refreshed) {
        accessToken = this.getAccessToken();
        if (accessToken) {
          const newHeaders = {
            ...options.headers,
            'Authorization': `Bearer ${accessToken}`
          };
          response = await fetch(url, { ...options, headers: newHeaders, credentials: 'include' });
        }
      }
    }

    return response;
  }

  /**
   * Oturum açmış mı kontrol et
   */
  async isLoggedIn(): Promise<boolean> {
    const user = await this.getUser();
    return user !== null;
  }

  /**
   * Device ID al
   */
  getDeviceId(): string {
    return this.deviceId;
  }
}

export default AuthHelper;