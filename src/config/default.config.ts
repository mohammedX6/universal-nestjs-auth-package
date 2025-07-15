/**
 * Default configuration for authentication across all microservices
 * This centralizes common settings and makes configuration consistent
 */

/**
 * Get access token expiration time from environment or default
 * @returns Expiration time in milliseconds
 */
export function accessTokenExpiration(): string {
  const envToken = process.env.ACCESS_TOKEN_EXPIRATION;

  const defaultToken = '1h';

  if (!envToken) {
    return defaultToken;
  }

  return envToken;
}

export function sessionExpiration(): number {
  const sessionExpiration = process.env.SESSION_EXPIRATION;

  const defaultSessionExpiration = 1 * 60 * 60 * 1000;

  if (!sessionExpiration) {
    return defaultSessionExpiration;
  }

  const parsedSessionExpiration = parseInt(sessionExpiration, 10);

  if (isNaN(parsedSessionExpiration) || parsedSessionExpiration <= 0) {
    return defaultSessionExpiration;
  }

  return parsedSessionExpiration;
}

export function sessionRememberMeExpiration(): number {
  const sessionRememberMeExpiration =
    process.env.SESSION_REMEMBER_ME_EXPIRATION;

  const defaultSessionRememberMeExpiration = 6 * 60 * 60 * 1000; // 6 hours in milliseconds

  if (!sessionRememberMeExpiration) {
    return defaultSessionRememberMeExpiration;
  }

  const parsedSessionRememberMeExpiration = parseInt(
    sessionRememberMeExpiration,
    10,
  );

  if (
    isNaN(parsedSessionRememberMeExpiration) ||
    parsedSessionRememberMeExpiration <= 0
  ) {
    return defaultSessionRememberMeExpiration;
  }

  return parsedSessionRememberMeExpiration;
}

export function refreshTokenExpiration(): string {
  const envToken = process.env.REFRESH_TOKEN_EXPIRATION;

  const defaultToken = '6h';

  if (!envToken) {
    return defaultToken;
  }

  return envToken;
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
    maxAge: sessionExpiration(),
    maxAgeRememberMe: sessionRememberMeExpiration(),
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
    jwt: {
      expiresIn: accessTokenExpiration(),
      refreshExpiresIn: refreshTokenExpiration(),
    },
    cookies: {
      names: {
        accessToken: 'access-token',
        refreshToken: 'refresh-token',
      },
      options: {
        httpOnly: true,
        secure: process.env.NODE_ENV?.toLowerCase() === 'production',
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
