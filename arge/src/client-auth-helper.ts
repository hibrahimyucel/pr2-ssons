interface AuthResponse {
  success: boolean;
  error?: string;
  user?: any;
  accessToken?: string;
  message?: string;
}

class AuthHelper {
  private authServiceUrl: string;
  private deviceId: string;

  constructor(authServiceUrl: string = 'http://localhost:3000') {
    this.authServiceUrl = authServiceUrl;
    this.deviceId = this.getOrCreateDeviceId();
  }

  /**
   * Cihaz ID'si oluştur veya mevcut olanı al
   * (Bu da cookie'de tutabiliriz, ancak localStorage basit)
   */
  private getOrCreateDeviceId(): string {
    // Session'da tut (aynı domain)
    if (!sessionStorage.getItem('deviceId')) {
      sessionStorage.setItem('deviceId', this.generateDeviceId());
    }
    return sessionStorage.getItem('deviceId')!;
  }

  private generateDeviceId(): string {
    return 'device_' + Math.random().toString(36).substr(2, 9) + '_' + Date.now();
  }

  async register(email: string, password: string, name: string): Promise<AuthResponse> {
    try {
      const response = await fetch(`${this.authServiceUrl}/api/auth/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Device-ID': this.deviceId
        },
        credentials: 'include', // ← Cookie'leri paylaş
        body: JSON.stringify({ email, password, name })
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Kayıt başarısız');
      }

      return { success: true, user: data.user };

    } catch (error) {
      const message = error instanceof Error ? error.message : 'Kayıt başarısız';
      console.error('Register hatası:', error);
      return { success: false, error: message };
    }
  }

  async login(email: string, password: string): Promise<AuthResponse> {
    try {
      const response = await fetch(`${this.authServiceUrl}/api/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Device-ID': this.deviceId
        },
        credentials: 'include', // ← Cookie'leri paylaş
        body: JSON.stringify({ email, password })
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Giriş başarısız');
      }

      return { success: true, user: data.user };

    } catch (error) {
      const message = error instanceof Error ? error.message : 'Giriş başarısız';
      console.error('Login hatası:', error);
      return { success: false, error: message };
    }
  }

  async getUser(): Promise<any | null> {
    try {
      const response = await fetch(`${this.authServiceUrl}/api/auth/me`, {
        credentials: 'include' // ← Cookie'ler otomatik gönderilir
      });

      if (response.status === 401) {
        const refreshed = await this.refreshAccessToken();
        if (refreshed) {
          return this.getUser();
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

  async refreshAccessToken(): Promise<boolean> {
    try {
      const response = await fetch(`${this.authServiceUrl}/api/auth/refresh`, {
        method: 'POST',
        headers: {
          'X-Device-ID': this.deviceId
        },
        credentials: 'include' // ← Refresh token cookie'den otomatik alınır
      });

      if (!response.ok) {
        return false;
      }

      return true;

    } catch (error) {
      console.error('Refresh hatası:', error);
      return false;
    }
  }

  async logout(): Promise<AuthResponse> {
    try {
      const response = await fetch(`${this.authServiceUrl}/api/auth/logout`, {
        method: 'POST',
        headers: {
          'X-Device-ID': this.deviceId
        },
        credentials: 'include' // ← Cookie'leri gönder
      });

      const data = await response.json();

      sessionStorage.clear();

      return { 
        success: response.ok, 
        message: data.message,
        error: !response.ok ? data.error : undefined
      };

    } catch (error) {
      console.error('Logout hatası:', error);
      sessionStorage.clear();
      const message = error instanceof Error ? error.message : 'Çıkış başarısız';
      return { success: false, error: message };
    }
  }

  /**
   * Access Token'ı al (Cookie'den)
   */
  getAccessToken(): string | null {
    return this.getCookie('accessToken');
  }

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
   * Authorized API call
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

  async isLoggedIn(): Promise<boolean> {
    const user = await this.getUser();
    return user !== null;
  }

  getDeviceId(): string {
    return this.deviceId;
  }
}

export default AuthHelper;