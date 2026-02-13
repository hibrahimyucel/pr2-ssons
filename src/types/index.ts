import { Request } from 'express';

export interface User {
  id: number;
  email: string;
  password?: string;
  name: string;
  created_at?: Date;
  updated_at?: Date;
  is_active: boolean;
}

export interface TokenPayload {
  email: string;
  userId: number;
  type: 'access' | 'refresh';
  iat?: number;
  exp?: number;
}

export interface AuthRequest extends Request {
  user?: TokenPayload;
  deviceId?: string;
}

export interface AuthResponse {
  success: boolean;
  error?: string;
  user?: Omit<User, 'password'>;
  accessToken?: string;
  refreshToken?: string;
  message?: string;
}

export interface LoginRequest {
  email: string;
  password: string;
}

export interface RegisterRequest extends LoginRequest {
  name: string;
}