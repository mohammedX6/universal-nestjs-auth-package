import { HttpException, HttpStatus } from '@nestjs/common';

/**
 * Base Authentication Exception
 * Provides consistent error handling across all authentication operations
 */
export abstract class AuthException extends HttpException {
  public readonly code: string;
  public readonly timestamp: Date;
  public readonly context?: string;

  constructor(
    message: string,
    status: HttpStatus,
    code: string,
    context?: string,
  ) {
    super(message, status);
    this.code = code;
    this.timestamp = new Date();
    this.context = context;
  }

  /**
   * Convert exception to JSON for logging/response
   */
  toJSON() {
    return {
      name: this.constructor.name,
      message: this.message,
      code: this.code,
      status: this.getStatus(),
      timestamp: this.timestamp,
      context: this.context,
    };
  }
}

/**
 * Authentication Failed Exception
 * Thrown when authentication credentials are invalid
 */
export class AuthenticationFailedException extends AuthException {
  constructor(message = 'Authentication failed', context?: string) {
    super(message, HttpStatus.UNAUTHORIZED, 'AUTH_FAILED', context);
  }
}

/**
 * Strategy Not Available Exception
 * Thrown when requested authentication strategy is not configured
 */
export class StrategyNotAvailableException extends AuthException {
  constructor(strategy: string, context?: string) {
    super(
      `Authentication strategy '${strategy}' is not available or configured`,
      HttpStatus.BAD_REQUEST,
      'STRATEGY_NOT_AVAILABLE',
      context,
    );
  }
}

/**
 * Configuration Error Exception
 * Thrown when authentication configuration is invalid
 */
export class ConfigurationException extends AuthException {
  constructor(message: string, context?: string) {
    super(message, HttpStatus.INTERNAL_SERVER_ERROR, 'CONFIG_ERROR', context);
  }
}

/**
 * Validation Error Exception
 * Thrown when input validation fails
 */
export class ValidationException extends AuthException {
  constructor(message: string, context?: string) {
    super(message, HttpStatus.BAD_REQUEST, 'VALIDATION_ERROR', context);
  }
}
