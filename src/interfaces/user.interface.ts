import { AuthMethod } from 'src/types/auth.types';

/**
 * Unified Authentication Result
 * Both JWT and Session authentication will return this format
 */
export interface IUser {
  userId: number;
  email: string;
}

export interface UnifiedAuthResult {
  user: IUser;
  authenticated: boolean;
  authMethod: AuthMethod;
  timestamp: Date;
  token?: string; // JWT token
  refreshToken?: string; // JWT refresh token
  sessionId?: string;
  tokenInfo?: {
    expiresAt?: Date;
    issuedAt?: Date;
  };
}

/**
 * Unified Authentication Input
 * Both JWT and Session authentication will accept this format
 */
export interface UnifiedAuthInput {
  userData: IUser;
  authMethod?: AuthMethod;
  options?: {
    expiresIn?: string | number;
    maxAge?: number;
    metadata?: Record<string, any>;
  };
}
