/**
 * Authentication Strategy Types
 */
export type AuthStrategy = 'jwt' | 'session' | 'hybrid';

/**
 * Authentication Method Types
 */
export type AuthMethod = 'jwt' | 'session' | 'auto';

/**
 * Authentication Status Types
 */
export type AuthStatus =
  | 'authenticated'
  | 'unauthenticated'
  | 'expired'
  | 'invalid';

/**
 * Session State Types
 */
export type SessionState = 'active' | 'expired' | 'revoked' | 'invalid';

/**
 * Device Types
 */
export type DeviceType = 'mobile' | 'tablet' | 'desktop' | 'unknown';

/**
 * Password Change Policy Types
 */
export type PasswordChangePolicy =
  | 'invalidate_all'
  | 'keep_current'
  | 'invalidate_others';

/**
 * Cookie SameSite Types
 */
export type CookieSameSite = 'strict' | 'lax' | 'none';

/**
 * Redis Configuration Types
 */
export interface RedisConfig {
  host: string;
  port: number;
  password?: string;
  db?: number;
  retryDelayOnFailover?: number;
  maxRetriesPerRequest?: number;
  connectTimeout?: number;
  lazyConnect?: boolean;
}

/**
 * JWT Configuration Types
 */
export interface JwtConfig {
  secret: string;
  expiresIn?: string;
  refreshExpiresIn?: string;
  algorithm?: string;
  issuer?: string;
  audience?: string;
}

/**
 * Session Configuration Types
 */
export interface SessionConfig {
  secret: string;
  name?: string;
  maxAge?: number;
  redis?: RedisConfig;
  multiSession?: {
    enabled: boolean;
    maxSessions?: number;
  };
  cookie?: {
    secure?: boolean;
    httpOnly?: boolean;
    sameSite?: CookieSameSite;
    domain?: string;
    path?: string;
  };
}

/**
 * Cookie Configuration Types
 */
export interface CookieConfig {
  names?: {
    accessToken?: string;
    refreshToken?: string;
  };
  options?: {
    httpOnly?: boolean;
    secure?: boolean;
    sameSite?: CookieSameSite;
    domain?: string;
    path?: string;
  };
  rememberMe?: {
    jwtMaxAge?: number;
    jwtRegularMaxAge?: number;
    refreshMaxAge?: number;
  };
}

/**
 * Google OAuth Configuration Types
 */
export interface GoogleOAuthConfig {
  clientId: string;
  clientSecret: string;
  callbackURL: string;
  scope?: string[];
}

/**
 * Validation Result Types
 */
export interface ValidationResult {
  isValid: boolean;
  errors: string[];
  warnings: string[];
}

/**
 * Configuration Validation Types
 */
export interface ConfigValidation {
  isValid: boolean;
  errors: string[];
  warnings: string[];
  suggestions: string[];
}
