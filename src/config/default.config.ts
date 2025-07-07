/**
 * Default configuration for authentication across all microservices
 * This centralizes common settings and makes configuration consistent
 */

/**
 * Get access token expiration time from environment or default
 * @returns Expiration time in milliseconds
 */
export function accessTokenExpiration(): number {
  const envToken = process.env.ACCESS_TOKEN_EXPIRATION;
  const defaultToken = 1 * 24 * 60 * 60 * 1000; // 1 day default

  if (!envToken) {
    return defaultToken;
  }

  const parsedToken = parseInt(envToken, 10);

  if (isNaN(parsedToken) || parsedToken <= 0) {
    return defaultToken;
  }
  return parsedToken;
}

/**
 * Get refresh token expiration time from environment or default
 * @returns Expiration time in milliseconds
 */
export function refreshTokenExpiration(): number {
  const envToken = process.env.REFRESH_TOKEN_EXPIRATION;
  const defaultToken = 2 * 24 * 60 * 60 * 1000; // 2 days default

  if (!envToken) {
    return defaultToken;
  }

  const parsedToken = parseInt(envToken, 10);

  if (isNaN(parsedToken) || parsedToken <= 0) {
    return defaultToken;
  }

  return parsedToken;
}

/**
 * Get default Redis configuration for sessions
 * Uses the same Redis connection as the main application
 * @returns Redis configuration object
 */
export function getDefaultRedisConfig() {
  return {
    host: process.env.REDIS_HOST || 'localhost',
    port: parseInt(process.env.REDIS_PORT) || 6379,
    db: parseInt(process.env.REDIS_SESSION_DB) || 0, // Use database 0 for sessions to separate from cache (db 0)
    ...(process.env.REDIS_PASSWORD && { password: process.env.REDIS_PASSWORD }),
  };
}

/**
 * Get default session configuration
 * Uses environment variables for app-specific naming or falls back to generic defaults
 * @returns Session configuration object
 */
export function getDefaultSessionConfig() {
  return {
    secret: process.env.JWT_SECRET_KEY || 'sawtak-session-secret',
    multiSession: {
      enabled: true,
      maxSessions: 3,
    },
    name: process.env.SESSION_NAME || 'sawtak-session-id',
    maxAge: accessTokenExpiration(),
    maxAgeRememberMe: 2 * 24 * 60 * 60 * 1000, // 2 days default
    redis: getDefaultRedisConfig(),
  };
}

/**
 * Get complete default AuthModule configuration
 * @returns Complete AuthModuleOptions with all defaults
 */
export function getDefaultAuthConfig() {
  return {
    strategy: 'session' as const,
    session: getDefaultSessionConfig(),
    cookies: {
      names: {
        accessToken: 'access-token',
        refreshToken: 'refresh-token',
      },
      options: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax' as const,
        path: '/',
      },
    },
  };
}

/**
 * Quick session configuration for microservices
 * Uses environment variables and sensible defaults
 * @param overrides - Optional configuration overrides
 * @returns Complete session configuration
 */
export function createSessionConfig(overrides?: Partial<any>) {
  const defaultConfig = getDefaultAuthConfig();
  return {
    ...defaultConfig,
    ...overrides,
    session: {
      ...defaultConfig.session,
      ...overrides?.session,
    },
  };
}
