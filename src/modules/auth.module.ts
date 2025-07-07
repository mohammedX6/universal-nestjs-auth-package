import { DynamicModule, Module } from '@nestjs/common';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { AuthService } from '../services/jwt/auth.service';
import { SessionService } from '../services/session/session.service';
import { JwtStrategyService } from '../services/jwt/jwt-strategy.service';
import { SessionStrategyService } from '../services/session/session-strategy.service';
import { AuthStrategyFactory } from '../services/auth-strategy.factory';
import { AuthHelperService } from '../services/auth-helper.service';
import { UnifiedAuthService } from '../services/unified-auth.service';
import { JwtStrategy } from '../strategies/jwt.strategy';
import { SessionModule } from './session.module';
import { DeviceDetectionService } from '../services/device-detection.service';
import { SessionStrategy } from '../strategies/session.strategy';
import { SessionGuard, OptionalSessionGuard } from '../guards/session.guard';
import {
  DynamicAuthGuard,
  OptionalDynamicAuthGuard,
  JwtOnlyGuard,
  SessionOnlyGuard,
} from '../guards/dynamic-auth.guard';
import { getDefaultAuthConfig } from '../config/default.config';
import { AuthStrategy } from 'src/types/auth.types';

export interface AuthModuleOptions {
  /**
   * Authentication strategy to use
   * 'jwt' - JWT token based authentication
   * 'session' - Session based authentication
   * 'hybrid' - Both JWT and session support
   */
  strategy: AuthStrategy;

  /**
   * JWT configuration (required if strategy includes JWT)
   */
  jwt?: {
    secret: string;
    expiresIn?: string;
    refreshExpiresIn?: string;
  };

  /**
   * Session configuration (required if strategy includes session)
   */
  session?: {
    secret: string;
    name?: string;
    maxAge?: number; // Base session duration in milliseconds (can be overridden by cookies.rememberMe settings)
    maxAgeRememberMe?: number; // Session duration in milliseconds for remember me (default: 7 days)
    redis?: {
      host: string;
      port: number;
      password?: string;
      db?: number;
    };
    multiSession?: {
      enabled: boolean;
      maxSessions?: number;
      // Removed sessionTimeout - use maxAge for consistency, cookies.rememberMe for dynamic behavior
    };
  };

  /**
   * Cookie configuration for JWT tokens only
   * Session configuration is handled in the session section above
   */
  cookies?: {
    // Cookie names configuration (JWT tokens only)
    names?: {
      accessToken?: string;
      refreshToken?: string;
    };
    // Cookie options configuration
    options?: {
      httpOnly?: boolean;
      secure?: boolean;
      sameSite?: 'strict' | 'lax' | 'none';
      domain?: string;
      path?: string;
    };
    // Remember me configuration (JWT tokens only)
    rememberMe?: {
      // JWT token expiration times
      jwtMaxAge?: number; // JWT token max age for remember me (default: 30 days)
      jwtRegularMaxAge?: number; // JWT token max age for regular login (default: 1 hour)
      refreshMaxAge?: number; // Refresh token max age for remember me (default: 30 days)
    };
  };
}

/**
 * Enhanced Auth Module with both JWT and Session support
 * Provides backward compatibility while adding session-based authentication
 */
@Module({})
export class AuthModule {
  /**
   * Configure the auth module with dynamic strategy selection
   * @param options - Configuration options for authentication strategies (optional, uses defaults if not provided)
   * @returns DynamicModule with configured providers
   */
  static forRoot(options?: AuthModuleOptions): DynamicModule {
    // Merge provided options with default configuration
    const defaultConfig = getDefaultAuthConfig() as AuthModuleOptions;
    const config: AuthModuleOptions = options
      ? {
          ...defaultConfig,
          ...options,
          // Deep merge session configuration if both exist
          session: options.session
            ? {
                ...defaultConfig.session,
                ...options.session,
                // Deep merge redis configuration if both exist
                redis: options.session?.redis
                  ? {
                      ...defaultConfig.session?.redis,
                      ...options.session.redis,
                    }
                  : defaultConfig.session?.redis,
                // Deep merge multiSession configuration if both exist
                multiSession: options.session?.multiSession
                  ? {
                      ...defaultConfig.session?.multiSession,
                      ...options.session.multiSession,
                    }
                  : defaultConfig.session?.multiSession,
              }
            : defaultConfig.session,
          // Deep merge JWT configuration if both exist
          jwt: options.jwt
            ? {
                ...defaultConfig.jwt,
                ...options.jwt,
              }
            : defaultConfig.jwt,
          // Deep merge cookies configuration if both exist
          cookies: options.cookies
            ? {
                ...defaultConfig.cookies,
                ...options.cookies,
                names: options.cookies?.names
                  ? {
                      ...defaultConfig.cookies?.names,
                      ...options.cookies.names,
                    }
                  : defaultConfig.cookies?.names,
                options: options.cookies?.options
                  ? {
                      ...defaultConfig.cookies?.options,
                      ...options.cookies.options,
                    }
                  : defaultConfig.cookies?.options,
                rememberMe: options.cookies?.rememberMe
                  ? {
                      ...defaultConfig.cookies?.rememberMe,
                      ...options.cookies.rememberMe,
                    }
                  : defaultConfig.cookies?.rememberMe,
              }
            : defaultConfig.cookies,
        }
      : defaultConfig;

    const providers = [];
    const imports = [];
    const exports = [];

    // Always include base services, strategy services, factory, unified services, and guards
    providers.push(
      AuthService,
      JwtStrategyService,
      SessionStrategyService,
      AuthStrategyFactory,
      UnifiedAuthService,
      AuthHelperService,
      DynamicAuthGuard,
      OptionalDynamicAuthGuard,
    );
    exports.push(
      AuthService,
      JwtStrategyService,
      SessionStrategyService,
      AuthStrategyFactory,
      UnifiedAuthService,
      AuthHelperService,
      DynamicAuthGuard,
      OptionalDynamicAuthGuard,
    );

    // Add PassportModule for all strategies
    imports.push(PassportModule);

    // Configure JWT strategy if needed
    if (config.strategy === 'jwt' || config.strategy === 'hybrid') {
      if (!config.jwt) {
        throw new Error(
          'JWT configuration is required when using JWT strategy',
        );
      }

      imports.push(
        JwtModule.register({
          secret: config.jwt.secret,
          signOptions: {
            expiresIn: config.jwt.expiresIn || '1h',
          },
        }),
      );

      providers.push(JwtStrategy, JwtOnlyGuard);
      exports.push(JwtStrategy, JwtOnlyGuard);
    }

    // Configure Session strategy if needed
    if (config.strategy === 'session' || config.strategy === 'hybrid') {
      // Use default session config if not provided
      const sessionConfig = config.session || getDefaultAuthConfig().session;

      // Use session name exactly as provided from config or environment, fallback to default
      const finalSessionConfig = {
        ...sessionConfig,
        name: sessionConfig.name || process.env.SESSION_NAME || 'sessionId',
      };

      imports.push(SessionModule.forRoot(finalSessionConfig));
      providers.push(
        SessionService,
        DeviceDetectionService,
        SessionStrategy,
        SessionGuard,
        OptionalSessionGuard,
        SessionOnlyGuard,
      );
      exports.push(
        SessionService,
        DeviceDetectionService,
        SessionStrategy,
        SessionGuard,
        OptionalSessionGuard,
        SessionOnlyGuard,
      );
    }

    return {
      module: AuthModule,
      imports,
      providers: [
        ...providers,
        // Provide the configuration for use in services
        {
          provide: 'AUTH_MODULE_OPTIONS',
          useValue: config,
        },
      ],
      exports: [
        ...exports,
        // Export the configuration so guards can access it globally
        'AUTH_MODULE_OPTIONS',
      ],
      global: true,
    };
  }
}
