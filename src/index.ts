// Core Authentication Module - Required for all microservices
export * from './modules/auth.module';

// Primary Authentication Services - Main services for authentication operations
export * from './services/unified-auth.service';
export * from './services/auth-helper.service';
export * from './services/auth-strategy.factory';

// Decorators - Used in controllers across all microservices
export * from './decorators/user.decorator';
export * from './decorators/token.decorator';
export * from './decorators/dynamic-auth.decorator';
export * from './decorators/session.decorator';

// Guards - Used for route protection
export * from './guards/dynamic-auth.guard';
export * from './guards/session.guard';

// Core Interfaces - Required for type definitions
export * from './interfaces/user.interface';
export * from './interfaces/auth-strategy.interface';
export * from './interfaces/session.interface';

// Professional Type Definitions - Enhanced type safety
export type {
  AuthStrategy,
  AuthMethod,
  AuthStatus,
  SessionState,
  DeviceType,
  CookieSameSite,
  RedisConfig,
  JwtConfig,
  CookieConfig,
  GoogleOAuthConfig,
  ValidationResult,
  ConfigValidation,
} from './types/auth.types';

// Exception Handling - Professional error management
export * from './exceptions/auth.exceptions';

// Utility Functions - Helper functions for authentication
export * from './utils/index';

// Configuration - Default configurations and helpers
export * from './config/default.config';

// Legacy JWT Service - Only for backward compatibility, use UnifiedAuthService instead
export * from './services/jwt/auth.service';

export * from './services/session/session.service';
