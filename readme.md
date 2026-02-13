# Auth Service - TypeScript

pr2-ssons

πr² Single Sign On Service

Birden fazla web uygulaması için merkezi **Single Sign-On (SSO)** çözümü sağlayan **authentication micro-service**.

> **sales.com**, **support.com** gibi farklı domain'lerdeki uygulamalarda kullanıcılar aynı cihazdan bir kez giriş yapınca tüm uygulamalarda otomatik olarak oturum açmış olurlar.

---

## 📋 İçindekiler

- [Proje Amacı](#proje-amacı)
- [Özellikler](#özellikler)
- [Teknoloji Stack](#🛠️-teknoloji-stack)
- [Sistem Gereksinimleri](#sistem-gereksinimleri)
- [Kurulum](#kurulum)
- [Kullanım](#kullanım)
- [API Endpoints](#api-endpoints)
- [Veritabanı Şeması](#veritabanı-şeması)
- [Klasör Yapısı](#klasör-yapısı)
- [Güvenlik](#güvenlik)
- [Production Hazırlığı](#production-hazırlığı)
- [Sorun Giderme](#sorun-giderme)

---

## Proje Amacı

Geleneksel single-application authentication sistemlerinin aksine, bu proje **birden fazla web uygulamasının aynı merkezi servisten yararlanmasını** sağlar.

### Kullanım Senaryosu

---

## Özellikler

### 🔐 Kimlik Doğrulama
- ✅ Email tabanlı kullanıcı kaydı (register)
- ✅ Şifre hash'leme (bcryptjs)
- ✅ Email/şifre ile giriş (login)

### 🎫 Token Yönetimi
- ✅ **Access Token** (15 dakika geçerli)
- ✅ **Refresh Token** (7 gün geçerli)
- ✅ Otomatik token yenileme
- ✅ Token doğrulama endpoint'i

### 📱 Cihaz Bazlı Oturum
- ✅ Cihaz kimliği (Device ID) ile oturum takibi
- ✅ Aynı cihazdan birden fazla login kaydı
- ✅ Cihaza özel token yönetimi

### 🌐 Multi-Domain Desteği
- ✅ CORS yapılandırması ile birden fazla domain desteği
- ✅ Her domain'de bağımsız session yönetimi
- ✅ Merkezi token kontrol

### 📊 Session Yönetimi
- ✅ Oturum geçmişi kaydı (audit log)
- ✅ Login/logout takibi
- ✅ IP adresi ve User-Agent kaydı

### 🗄️ Veritabanı
- ✅ MariaDB/MySQL desteği
- ✅ Connection pool (10 eş zamanlı bağlantı)
- ✅ Güvenli query'ler (parameterized)

---

## 🛠️ Teknoloji Stack

| Kategori | Teknoloji |
|----------|-----------|
| **Runtime** | Node.js (v14+) |
| **Language** | TypeScript 5.3+ |
| **Framework** | Express.js 4.18+ |
| **Veritabanı** | MariaDB / MySQL |
| **Authentication** | JWT (jsonwebtoken) |
| **Password Hash** | bcryptjs |
| **CORS** | cors |
| **Environment** | dotenv |

---

## 📦 Sistem Gereksinimleri

Kurulum öncesi bilgisayarınızda bunlar yüklü olmalı:

### Zorunlu
- **Node.js** v14+ ([nodejs.org](https://nodejs.org))
- **npm** v6+ (Node.js ile birlikte gelir)
- **MariaDB** v10.3+ ([mariadb.org](https://mariadb.org)) VEYA **MySQL** v5.7+

### Opsiyonel
- **Git** (repository klonlamak için)
- **Postman** (API test etmek için)
- **VS Code** (geliştirme için)

### Kontrol Et
```bash
node --version    # v14.0.0 veya daha yüksek
npm --version     # v6.0.0 veya daha yüksek
mysql --version   # MySQLi client v5.7 veya daha yüksek
```

## 🚀 Kurulum

###  1️⃣ Proje Klasörünü Oluştur
```bash
mkdir auth-service-typescript
cd auth-service-typescript
```

###  2️⃣ Git Repository'sini İndir (veya manuel dosya oluştur)
```bash
git clone <repo-url> .
# veya dosyaları manuel olarak oluştur
```

### 3️⃣ Bağımlılıkları Yükle
```bash
npm install express jsonwebtoken bcryptjs mysql2 cors dotenv
npm install -D typescript @types/express @types/node @types/jsonwebtoken @types/bcryptjs nodemon ts-node
```

**Yüklenen paketler:**

-   `express`  - Web server framework
-   `jsonwebtoken`  - JWT token oluşturma/doğrulama
-   `bcryptjs`  - Şifre hash'leme
-   `mysql2`  - MariaDB/MySQL driver
-   `cors`  - Cross-Origin Resource Sharing
-   `dotenv`  - Environment değişkenleri
-   `typescript`,  `ts-node`,  `@types/*`  - TypeScript support


### 4️⃣ Veritabanını Oluştur

```sql
-- Veritabanı oluştur
CREATE DATABASE auth_service CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE auth_service;

-- Users tablosu
CREATE TABLE users (
  id INT PRIMARY KEY AUTO_INCREMENT,
  email VARCHAR(255) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,
  name VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_active BOOLEAN DEFAULT TRUE,
  INDEX idx_email (email)
);

-- Refresh Tokens tablosu
CREATE TABLE refresh_tokens (
  id INT PRIMARY KEY AUTO_INCREMENT,
  user_id INT NOT NULL,
  token LONGTEXT NOT NULL,
  device_id VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  expires_at DATETIME NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_user_device (user_id, device_id),
  INDEX idx_expires_at (expires_at)
);

-- Session History tablosu (audit log)
CREATE TABLE session_history (
  id INT PRIMARY KEY AUTO_INCREMENT,
  user_id INT NOT NULL,
  device_id VARCHAR(255) NOT NULL,
  action VARCHAR(50),
  ip_address VARCHAR(45),
  user_agent TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_user_created (user_id, created_at)
);

-- Kontrol et
SHOW TABLES;
DESCRIBE users;

-- Çık
EXIT;
```

### 5️⃣ Environment Değişkenlerini Ayarla

`.env`  dosyası oluştur ve şunları ekle:
```

# === VERITABANI ===
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=your_mysql_password  # Senin MySQL şifreni yazı
DB_NAME=auth_service
# === JWT SECRETS ===
# Production'da GÜÇLÜ ve RANDOM değerler kullan!
ACCESS_TOKEN_SECRET=your_super_secret_access_token_key_change_this_in_production
REFRESH_TOKEN_SECRET=your_super_secret_refresh_token_key_change_this_too

# === SERVER ===
PORT=3000
NODE_ENV=development

# === CORS (İzin Verilecek Domainler) ===
ALLOWED_DOMAINS=localhost:3000,localhost:3001,sales.local:3000,support.local:3000

```

**⚠️ Önemli:**

-   `DB_PASSWORD`  yerine kendi MySQL-MariaDB şifreni yaz.
-   Production'da  `ACCESS_TOKEN_SECRET`  ve  `REFRESH_TOKEN_SECRET`'i güçlü, random değerlerle değiştir.

### 6️⃣ Geliştirme Modunda Çalıştır

```bash
npm run dev
# sonuç
Veritabanı bağlantısı başarılı
Auth Service 3000 portunda çalışıyor
```

### 7️⃣ (Opsiyonel) Production İçin Derle

```bash
npm run build
npm start
```


### API Testi (cURL)
### API Testi (cURL)

#### Kayıt Ol

bash

```
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -H "X-Device-ID: device_chrome_123" \
  -d '{
    "email": "user@example.com",
    "password": "sifre123",
    "name": "Ahmet Yilmaz"
  }'

```

**Dönüş:**

JSON

```
{
  "message": "Kullanıcı başarıyla oluşturuldu",
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": 1,
    "email": "user@example.com",
    "name": "Ahmet Yilmaz"
  }
}

```

#### Giriş Yap

bash

```
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -H "X-Device-ID: device_chrome_123" \
  -d '{
    "email": "user@example.com",
    "password": "sifre123"
  }'

```

#### Profil Bilgisi Al

bash

```
curl -X GET http://localhost:3000/api/auth/me \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"

```

#### Token'ı Yenile

bash

```
curl -X POST http://localhost:3000/api/auth/refresh \
  -H "Content-Type: application/json" \
  -H "X-Device-ID: device_chrome_123" \
  -d '{
    "refreshToken": "YOUR_REFRESH_TOKEN"
  }'

```

#### Çıkış Yap

bash

```
curl -X POST http://localhost:3000/api/auth/logout \
  -H "Content-Type: application/json" \
  -H "X-Device-ID: device_chrome_123" \
  -d '{
    "refreshToken": "YOUR_REFRESH_TOKEN"
  }'

```

#### Token Doğrula (Diğer Servisler İçin)

bash

```
curl -X POST http://localhost:3000/api/auth/verify \
  -H "Content-Type: application/json" \
  -d '{
    "accessToken": "YOUR_ACCESS_TOKEN"
  }'

```

### Web Uygulamasında Kullan

**HTML + JavaScript:**

HTML

```
<!DOCTYPE html>
<html>
<head>
  <title>Sales.com</title>
</head>
<body>
  <h1>Sales Uygulaması</h1>
  
  <input type="email" id="email" placeholder="Email">
  <input type="password" id="password" placeholder="Şifre">
  <button onclick="login()">Giriş Yap</button>
  <button onclick="getProfile()">Profili Gör</button>
  <button onclick="logout()">Çıkış Yap</button>

  <div id="result"></div>

  <script>
    const authServiceUrl = 'http://localhost:3000';
    let deviceId = localStorage.getItem('deviceId');
    
    if (!deviceId) {
      deviceId = 'device_' + Math.random().toString(36).substr(2, 9);
      localStorage.setItem('deviceId', deviceId);
    }

    async function login() {
      const email = document.getElementById('email').value;
      const password = document.getElementById('password').value;

      const response = await fetch(`${authServiceUrl}/api/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Device-ID': deviceId
        },
        body: JSON.stringify({ email, password })
      });

      const data = await response.json();
      
      if (response.ok) {
        localStorage.setItem('accessToken', data.accessToken);
        localStorage.setItem('refreshToken', data.refreshToken);
        document.getElementById('result').innerHTML = `
          Hoşgeldiniz, ${data.user.name}!
        `;
      } else {
        document.getElementById('result').innerHTML = `Hata: ${data.error}`;
      }
    }

    async function getProfile() {
      const accessToken = localStorage.getItem('accessToken');
      
      const response = await fetch(`${authServiceUrl}/api/auth/me`, {
        headers: {
          'Authorization': `Bearer ${accessToken}`
        }
      });

      const user = await response.json();
      document.getElementById('result').innerHTML = JSON.stringify(user, null, 2);
    }

    async function logout() {
      const refreshToken = localStorage.getItem('refreshToken');
      
      await fetch(`${authServiceUrl}/api/auth/logout`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Device-ID': deviceId
        },
        body: JSON.stringify({ refreshToken })
      });

      localStorage.clear();
      document.getElementById('result').innerHTML = 'Çıkış yaptınız';
    }
  </script>
</body>
</html>

```

----------

## 📡 API Endpoints

Method

Endpoint

Header

Body

İşlev

POST

`/api/auth/register`

X-Device-ID

email, password, name

Yeni kullanıcı kayıt

POST

`/api/auth/login`

X-Device-ID

email, password

Kullanıcı giriş

POST

`/api/auth/refresh`

X-Device-ID

refreshToken

Access token yenile

GET

`/api/auth/me`

Authorization

-

Mevcut kullanıcı bilgisi

POST

`/api/auth/logout`

X-Device-ID

refreshToken

Oturum kapat

POST

`/api/auth/verify`

- accessToken

Token doğrulama (diğer servisler için)

### Header Açıklaması

Code

```
X-Device-ID: Cihaza özgü benzersiz kimlik (localStorage'da tutulur)
Authorization: Bearer <accessToken>

```

----------

## 🗄️ Veritabanı Şeması

### users tablosu

SQL

```
+----------+-------------+------+-----+---------+------+
| Field    | Type        | Null | Key | Default |
+----------+-------------+------+-----+---------+------+
| id       | INT         | NO   | PRI | AUTO    |
| email    | VARCHAR(255)| NO   | UNI | NULL    |
| password | VARCHAR(255)| NO   |     | NULL    |
| name     | VARCHAR(255)| NO   |     | NULL    |
| created_at | TIMESTAMP | NO   |     | NOW()   |
| updated_at | TIMESTAMP | NO   |     | NOW()   |
| is_active  | BOOLEAN   | NO   |     | TRUE    |
+----------+-------------+------+-----+---------+------+

```

### refresh_tokens tablosu

SQL

```
+------------+-----------+------+-----+---------+
| Field      | Type      | Null | Key | Default |
+------------+-----------+------+-----+---------+
| id         | INT       | NO   | PRI | AUTO    |
| user_id    | INT       | NO   | FK  | NULL    |
| token      | LONGTEXT  | NO   |     | NULL    |
| device_id  | VARCHAR   | NO   | MUL | NULL    |
| created_at | TIMESTAMP | NO   |     | NOW()   |
| expires_at | DATETIME  | NO   |     | NULL    |
+------------+-----------+------+-----+---------+

```

### session_history tablosu

SQL
```
| Field    | Type     | Null | Key | Default |
----------------------------------------------
| id       | INT      | NO   | PRI | AUTO    |
| user_id  | INT      | NO   | FK  | NULL    |
| device_id| VARCHAR  | NO   | MUL | NULL    |
| action   | VARCHAR  | YES  |     | NULL    |
| ip_address | VARCHAR| YES  |     | NULL    |
| user_agent | TEXT   | YES  |     | NULL    |
| created_at | TIMESTAMP | NO |     | NOW()   |
```



----------

## 📁 Klasör Yapısı

Code

```
auth-service-typescript/
│
├── src/
│   ├── auth-service.ts           # Ana server dosyası
│   ├── database.ts               # Veritabanı işlemleri
│   ├── token.ts                  # JWT token işlemleri
│   ├── middleware.ts             # Express middleware'ler
│   ├── routes/
│   │   └── auth.ts               # Auth route'ları
│   └── types/
│       └── index.ts              # TypeScript tipler
│
├── dist/                         # Derlenmiş JavaScript (build sonrası)
│
├── .env                          # Environment değişkenleri (local)
├── .env.example                  # Example environment (repo'da)
├── .gitignore                    # Git ignore kuralları
├── tsconfig.json                 # TypeScript yapılandırması
├── package.json                  # Node.js bağımlılıkları
├── package-lock.json             # Exact dependency versions
│
└── README.md                     # Bu dosya

```

----------

## 🔒 Güvenlik

### Best Practices

✅  **Şifre Hash'leme**

-   bcryptjs ile 10 rounds hash'leme
-   Plain text şifreler asla saklanmaz

✅  **JWT Token Güvenliği**

-   Access Token: 15 dakika geçerli (kısa)
-   Refresh Token: 7 gün geçerli (uzun)
-   Secrets: Strong, random değerler (production)

✅  **CORS Yapılandırması**

-   Sadece whitelisted domain'lere izin
-   Credentials support

✅  **SQL Injection Koruması**

-   Parameterized queries (mysql2)
-   Hiçbir dinamik SQL kullanılmaz

✅  **Device-Based Sessions**

-   Her cihazın kendi token'ı
-   Çalınan token'lar sadece o cihazda geçerli

### Production İçin Kontrol Listesi

-   `.env`  dosyasını  `.gitignore`'a ekle
-   `ACCESS_TOKEN_SECRET`  ve  `REFRESH_TOKEN_SECRET`'i güçlü, random değerlerle değiştir
-   HTTPS kullan (SSL/TLS)
-   Database backup'ını otomatik yap
-   Rate limiting ekle (brute-force koruması)
-   Logging & monitoring kur
-   Database user'ın yalnızca gerekli permission'ları olsun

----------

## 🚀 Production Hazırlığı

### 1. Environment Değişkenlerini Güncelle

```
# Güçlü secret'lar oluştur
openssl rand -base64 32  # Access token secret
openssl rand -base64 32  # Refresh token secret

# .env dosyasını güncelle
ACCESS_TOKEN_SECRET=<generated-secret-1>
REFRESH_TOKEN_SECRET=<generated-secret-2>
NODE_ENV=production

```

### 2. CORS Yapılandırmasını Ayarla

```
# .env
ALLOWED_DOMAINS=sales.com,support.com,admin.com

```

### 3. Build Et ve Çalıştır

```
npm run build
npm start

```

### 4. PM2 ile Process Manager Kur (İsteğe Bağlı)

```
npm install -g pm2
pm2 start dist/auth-service.js --name "auth-service"
pm2 startup
pm2 save
pm2 logs auth-service

```

### 5. Nginx/Apache ile Reverse Proxy (İsteğe Bağlı)

Nginx
```
server {
    listen 80;
    server_name auth-service.example.com;

    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}

```

----------

## 🐛 Sorun Giderme

### Sorun: "Could not find a declaration file for module 'cors'"

**Çözüm:**
```
npm install -D @types/cors

```

### Sorun: "Parameter 'err' implicitly has an 'any' type"

**Çözüm:**  TypeScript strict mode açık. Type'ı ekle:

TypeScript
```
jwt.verify(token, secret, (err: Error | null, user: any) => {
  // ...
});

```

### Sorun: "Access denied for user 'root'@'localhost'"

**Çözüm:**  MySQL password'ü kontrol et:

```
# .env dosyasındaki DB_PASSWORD'ü doğru yaz
DB_PASSWORD=your_actual_mysql_password

```

### Sorun: "Cannot find module 'dotenv'"

**Çözüm:**

```
npm install dotenv

```

### Sorun: "ECONNREFUSED 127.0.0.1:3306"

**Çözüm:**  MySQL server çalışmıyor:

bash

```
# Windows
net start MySQL80

# macOS
brew services start mysql

# Linux
sudo systemctl start mysql

```

### Sorun: "Port 3000 already in use"

**Çözüm:**  Port'ı değiştir:

bash

```
# .env
PORT=3001

```

----------

## 📚 Kaynaklar

-   [Express.js Documentation](https://expressjs.com/)
-   [TypeScript Handbook](https://www.typescriptlang.org/docs)
-   [JWT.io](https://jwt.io/)
-   [MySQL Documentation](https://dev.mysql.com/doc)
-   [MariaDB Documentation](https://mariadb.com/kb)

----------

## 📝 Lisans

MIT License

----------

## 💬 Sorular & Destek

Sorularınız veya önerileri için  **GitHub Issues**  açabilirsiniz.

----------

## 🎉 Katkı Yapanlar

-   **Geliştirici:**  hibrahimyucel

----------

**Happy Coding! 🚀**

```
✅ Proje amacı ve özeti  
✅ Tüm özellikler detaylı  
✅ Sistem gereksinimleri  
✅ Adım adım kurulum  
✅ API endpoint'leri  
✅ Veritabanı şeması  
✅ Klasör yapısı  
✅ Güvenlik best practices  
✅ Production hazırlığı  
✅ Sorun giderme  
✅ Kaynaklar  

Uygulanabilir ve yeni gelenler için açık! 📖
```

# Auth Service TypeScript

## Project Purpose
This project is designed to provide a robust and scalable authentication service written in TypeScript. The goal is to offer secure user authentication for applications while ensuring ease of integration and flexibility for developers.

## Features
- **User Registration**: Secure user registration with password hashing.
- **User Login**: Authentication with JWT-based token generation.
- **Password Reset**: Mechanism for users to reset their passwords securely.
- **Role Management**: Support for user roles and permissions.
- **Two-Factor Authentication (2FA)**: Integration for improved security.

## Setup Instructions
### Prerequisites
1. Node.js (version 14 or above)
2. npm or yarn
3. MongoDB (for storing user data)

### Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/username/auth-service-typescript.git
   cd auth-service-typescript
   ```

2.  Install dependencies:
    ```
    npm install
    # or
    yarn install
    
    ```
    
3.  Create a .env file in the root directory and configure the necessary environment variables such as:
    ```
    MONGO_URI=your_mongo_uri
    JWT_SECRET=your_jwt_secret
    
    ```
    
4.  Run the application:
   
    
    ```
    npm start
    # or
    yarn start
    
    ```
    

### Testing

To run tests, execute:


```
npm test
# or
yarn test

```

### Contribution

Feel free to submit issues or pull requests to improve the project!


# planlama

### Copilot said: Harika soru! Production'a geçmeden önce önemli önerileri

Harika soru! Production'a geçmeden önce önemli önerileri not alayım: 📝

RECOMMENDATIONS.md

```
# Auth Service - Geliştirilmesi İçin Öneriler

## 🔒 Güvenlik (Kritik)

### 1. Rate Limiting (Brute-force Koruması)
```typescript

```

### 2. HTTPS/SSL Zorunlu

-   Production'da HTTPS kullan
-   Self-signed certificate test'te yeterli
-   Let's Encrypt free certificate kullan

### 3. Token Blacklist (Çalınan Token'ı Bloke Etme)

TypeScript

```
// src/token-blacklist.ts
const blacklistedTokens = new Set<string>();

export function blacklistToken(token: string): void {
  blacklistedTokens.add(token);
}

export function isTokenBlacklisted(token: string): boolean {
  return blacklistedTokens.has(token);
}

```

### 4. CORS Stricter Yapılandırması

TypeScript

```
// Whitelist'i environment'tan oku
const whitelist = process.env.ALLOWED_DOMAINS?.split(',') || [];

const corsOptions = {
  origin: (origin: string, callback: Function) => {
    if (whitelist.includes(origin) || !origin) {
      callback(null, true);
    } else {
      callback(new Error('CORS hatası'));
    }
  },
  credentials: true,
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));

```

### 5. Input Validation (Sanitization)

bash

```
npm install joi
# veya
npm install zod

```

TypeScript

```
import Joi from 'joi';

const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(6).max(100).required()
});

app.post('/api/auth/login', async (req, res) => {
  const { error, value } = loginSchema.validate(req.body);
  if (error) {
    return res.status(400).json({ error: error.details[0].message });
  }
  // ...
});

```

### 6. Helmet.js (HTTP Headers Güvenliği)

bash

```
npm install helmet

```

TypeScript

```
import helmet from 'helmet';

app.use(helmet());

```

----------

## 📊 Logging & Monitoring (Önemli)

### 1. Winston Logger

bash

```
npm install winston

```

TypeScript

```
import winston from 'winston';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' })
  ]
});

logger.info('User logged in', { userId: 1, email: 'user@example.com' });
logger.error('Database error', { error: err.message });

```

### 2. Request Logging (Morgan)

bash

```
npm install morgan

```

TypeScript

```
import morgan from 'morgan';

app.use(morgan('combined')); // HTTP request logs

```

### 3. Error Tracking (Sentry)

bash

```
npm install @sentry/node

```

TypeScript

```
import * as Sentry from "@sentry/node";

Sentry.init({ dsn: process.env.SENTRY_DSN });

app.use(Sentry.Handlers.errorHandler());

```

----------

## 🗄️ Veritabanı (Önemli)

### 1. Database Migrations

bash

```
npm install flyway-cli
# veya
npm install db-migrate

```

### 2. Connection Pooling İyileştirmesi

TypeScript

```
// Mevcut yapı iyi, ama monitoring ekle
setInterval(() => {
  const stats = (pool as any)._allConnections?.length || 0;
  const free = (pool as any)._freeConnections?.length || 0;
  console.log(`DB Pool: ${free}/${stats} serbest`);
  
  // Alert: Pool dolu mu?
  if (free < 2) {
    logger.warn('Database pool neredeyse dolu!');
  }
}, 30000);

```

### 3. Query Performance Optimization

TypeScript

```
// Slow query logs
export async function logSlowQuery(query: string, executionTime: number) {
  if (executionTime > 1000) { // 1 saniye
    logger.warn('Slow query detected', { query, executionTime });
  }
}

```

### 4. Data Encryption (Sensitive Data İçin)

bash

```
npm install crypto-js

```

TypeScript

```
import CryptoJS from 'crypto-js';

export function encryptSensitiveData(data: string): string {
  return CryptoJS.AES.encrypt(data, process.env.ENCRYPTION_KEY!).toString();
}

export function decryptSensitiveData(encryptedData: string): string {
  return CryptoJS.AES.decrypt(encryptedData, process.env.ENCRYPTION_KEY!)
    .toString(CryptoJS.enc.Utf8);
}

```

----------

## 🔄 DevOps & Deployment (Önemli)

### 1. Docker Container

Dockerfile

```
FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

```

Dockerfile.dev

```
FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install

```

### 2. Docker Compose (Local Development)

docker-compose.yml

```
version: '3.8'

services:
  mariadb:
    image: mariadb:10.6
    environment:

```

### 3. CI/CD Pipeline (GitHub Actions)

.github/workflows/ci.yml

```
name: CI/CD

on:
  push:
    branches: [main, develop]
  pull_request:

```

----------

## 🧪 Testing (Önemli)

### 1. Unit Tests

bash

```
npm install --save-dev jest @types/jest ts-jest

```

jest.config.json

```
{
  "preset": "ts-jest",
  "testEnvironment": "node",
  "roots": ["<rootDir>/src"],
  "testMatch": ["**/__tests__/**/*.ts", "**/?(*.)+(spec|test).ts"]
}

```

src/token.test.ts

```
import { generateAccessToken, verifyAccessToken } from './token';

describe('Token Utils', () => {
  it('should generate valid access token', () => {
    const token = generateAccessToken('test@example.com', 1);
    expect(token).toBeDefined();

```

### 2. Integration Tests

bash

```
npm install --save-dev supertest @types/supertest

```

TypeScript

```
import request from 'supertest';
import app from '../auth-service';

describe('Auth API', () => {
  it('should register user', async () => {
    const response = await request(app)
      .post('/api/auth/register')
      .set('X-Device-ID', 'test-device')
      .send({
        email: 'test@example.com',
        password: 'password123',
        name: 'Test User'
      });

    expect(response.status).toBe(201);
    expect(response.body.accessToken).toBeDefined();
  });
});

```

----------

## 📈 Scalability & Performance

### 1. Redis Caching (Token Blacklist, Session Cache)

bash

```
npm install redis

```

TypeScript

```
import { createClient } from 'redis';

const redisClient = createClient({
  host: process.env.REDIS_HOST || 'localhost',
  port: parseInt(process.env.REDIS_PORT || '6379')
});

// Token blacklist'i Redis'e kaydet
export async function blacklistToken(token: string): Promise<void> {
  await redisClient.setEx(`blacklist:${token}`, 3600, '1');
}

// Kontrol et
export async function isTokenBlacklisted(token: string): Promise<boolean> {
  return await redisClient.exists(`blacklist:${token}`) > 0;
}

```

### 2. Database Query Optimization

-   Index'leri sık kontrol et
-   N+1 query problem'ini çöz
-   Slow query log'ları izle

### 3. Load Balancing (Multiple Instances)

nginx.conf

```
upstream auth_service {
  least_conn;
  server localhost:3000;
  server localhost:3001;
  server localhost:3002;
}

```

----------

## 🔔 Feature Ideas (Gelecek)

### 1. Email Verification

TypeScript

```
// E-mail doğrulama sms gönder
// Kullanıcı doğrulama kodını gir
// Email verified flag'i güncelle

```

### 2. Password Reset Mechanism

TypeScript

```
// Token ile reset link gönder
// Reset token geçici (15 dakika)
// Yeni şifre hash'le ve kaydet

```

### 3. OAuth2 Integration (Google, GitHub)

bash

```
npm install passport passport-google-oauth20

```

### 4. Two-Factor Authentication (2FA)

bash

```
npm install speakeasy qrcode

```

### 5. Refresh Token Rotation

TypeScript

```
// Her refresh'te yeni refresh token oluştur
// Eski refresh token'ı geçersiz kıl
// Session hijacking'i engelle

```

### 6. API Key Authentication

TypeScript

```
// Long-lived API keys
// Rate limiting per API key
// Usage tracking

```

----------

## 📚 Documentation (Tavsiye Edilen)

### 1. API Documentation (Swagger/OpenAPI)

bash

```
npm install swagger-ui-express swagger-jsdoc

```

TypeScript

```
// src/swagger.ts
import swaggerJsdoc from 'swagger-jsdoc';

const options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Auth Service API',
      version: '1.0.0',
      description: 'Authentication Micro-service'
    },
    servers: [{ url: 'http://localhost:3000' }]
  },
  apis: ['./src/routes/*.ts']
};

export const swaggerSpec = swaggerJsdoc(options);

```

### 2. Architecture Diagram

-   Miro/Lucidchart'ta diagram çiz
-   README'ye ekle

### 3. Deployment Guide

-   Docker setup
-   Environment variables
-   Database migration
-   Health checks

----------

## ✅ Pre-Production Checklist

-   HTTPS/SSL certificate var
-   Rate limiting ekli
-   Logging configured
-   Database backups scheduled
-   Error handling comprehensive
-   Input validation active
-   Tests passing (%80+ coverage)
-   Docker image built & tested
-   CI/CD pipeline working
-   Load testing done
-   Security audit passed
-   Documentation complete
-   Environment variables documented
-   Monitoring tools setup
-   Incident response plan ready

----------

## 🎯 Öncelik Sırası

1.  **Hemen**  (Bu hafta)
    
    -   Rate limiting
    -   Input validation
    -   Helmet.js
    -   Logging
2.  **Yakında**  (Bu ay)
    
    -   Docker setup
    -   Tests (%60+)
    -   Redis caching
    -   Email verification
3.  **Sonra**  (Gelecek ay)
    
    -   OAuth2
    -   2FA
    -   Advanced monitoring
    -   Load testing

----------

## 📞 Sorular?

Bu önerilerden hangisini önce implement etmek istersen, adım adım yazabilirim! 🚀

Code

```

Bu dosyayı `RECOMMENDATIONS.md` olarak proje klasörüne ekle. İçeriyor:

✅ Güvenlik (kritik)  
✅ Logging & Monitoring  
✅ Veritabanı optimizasyonu  
✅ DevOps & Deployment  
✅ Testing stratejisi  
✅ Scalability  
✅ Feature ideas  
✅ Documentation  
✅ Pre-production checklist  
✅ Öncelik sırası  

Hangisini ilk implement etmek istersen, tüm kodla yardımcı olurum! 💪🚀

```