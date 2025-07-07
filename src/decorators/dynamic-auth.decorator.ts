import { applyDecorators, UseGuards, SetMetadata } from '@nestjs/common';
import {
  DynamicAuthGuard,
  OptionalDynamicAuthGuard,
  JwtOnlyGuard,
  SessionOnlyGuard,
} from '../guards/dynamic-auth.guard';

/**
 * Dynamic authentication decorator options
 */
export interface DynamicAuthOptions {
  /**
   * Force a specific authentication strategy
   * If not specified, will auto-detect based on request
   */
  strategy?: 'jwt' | 'session' | 'auto';

  /**
   * Whether authentication is optional
   * If true, request continues even if no valid auth is found
   */
  optional?: boolean;
}

/**
 * Dynamic Authentication Decorator
 * Automatically selects the appropriate authentication strategy based on the request
 * Can be used on both classes and methods
 *
 * @param options - Authentication options
 *
 * @example
 * // Class-level authentication (applies to all methods)
 * @DynamicAuth()
 * @Controller('api')
 * export class ApiController { ... }
 *
 * @example
 * // Method-level authentication
 * @Get('profile')
 * @DynamicAuth()
 * async getProfile() { ... }
 *
 * @example
 * // Force JWT authentication
 * @DynamicAuth({ strategy: 'jwt' })
 * async getJwtData() { ... }
 *
 * @example
 * // Force session authentication
 * @DynamicAuth({ strategy: 'session' })
 * async getSessionData() { ... }
 *
 * @example
 * // Optional authentication (doesn't fail if no auth)
 * @DynamicAuth({ optional: true })
 * async getOptionalData() { ... }
 */
export function DynamicAuth(options: DynamicAuthOptions = {}) {
  const { strategy = 'auto', optional = false } = options;

  let guard: any;

  switch (strategy) {
    case 'jwt':
      guard = JwtOnlyGuard;
      break;
    case 'session':
      guard = SessionOnlyGuard;
      break;
    case 'auto':
    default:
      guard = optional ? OptionalDynamicAuthGuard : DynamicAuthGuard;
      break;
  }

  // Create the decorator that works for both classes and methods
  const decorator = applyDecorators(
    UseGuards(guard),
    SetMetadata('auth:strategy', strategy),
    SetMetadata('auth:optional', optional),
  );

  return decorator;
}

/**
 * Convenience decorators for specific strategies
 */

/**
 * JWT-only authentication decorator
 * Forces JWT authentication regardless of module configuration
 * Can be used on both classes and methods
 */
export function JwtAuth() {
  return DynamicAuth({ strategy: 'jwt' });
}

/**
 * Session-only authentication decorator
 * Forces session authentication regardless of module configuration
 * Can be used on both classes and methods
 */
export function SessionAuth() {
  return DynamicAuth({ strategy: 'session' });
}

/**
 * Optional authentication decorator
 * Attempts authentication but doesn't fail if none found
 * Can be used on both classes and methods
 */
export function OptionalAuth() {
  return DynamicAuth({ optional: true });
}
