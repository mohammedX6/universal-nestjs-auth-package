import { Injectable, Inject, Optional } from '@nestjs/common';
import {
  IAuthStrategy,
  IAuthStrategyFactory,
} from '../interfaces/auth-strategy.interface';
import { JwtStrategyService } from './jwt/jwt-strategy.service';
import { SessionStrategyService } from './session/session-strategy.service';
import { AuthModuleOptions } from '../modules/auth.module';
import {
  StrategyNotAvailableException,
  ConfigurationException,
} from '../exceptions/auth.exceptions';

/**
 * Authentication Strategy Factory
 * Provides the appropriate authentication strategy based on configuration
 * Supports JWT, Session, and Hybrid modes
 */
@Injectable()
export class AuthStrategyFactory implements IAuthStrategyFactory {
  constructor(
    private readonly jwtStrategy: JwtStrategyService,
    private readonly sessionStrategy: SessionStrategyService,
    @Optional()
    @Inject('AUTH_MODULE_OPTIONS')
    private readonly authOptions?: AuthModuleOptions,
  ) {
    this.validateConfiguration();
  }

  /**
   * Validate configuration on initialization
   * @private
   */
  private validateConfiguration(): void {
    if (!this.authOptions) {
      return; // Use defaults
    }

    const strategy = this.authOptions.strategy;
    if (!['jwt', 'session', 'hybrid'].includes(strategy)) {
      throw new ConfigurationException(
        `Invalid authentication strategy: ${strategy}. Must be 'jwt', 'session', or 'hybrid'`,
      );
    }
  }

  /**
   * Create authentication strategy based on type
   * @param type - Strategy type ('jwt' or 'session')
   * @returns Authentication strategy instance
   */
  createStrategy(type: 'jwt' | 'session'): IAuthStrategy {
    switch (type) {
      case 'jwt':
        if (!this.jwtStrategy.isAvailable()) {
          throw new StrategyNotAvailableException(
            'jwt',
            'JWT strategy configuration missing or invalid',
          );
        }
        return this.jwtStrategy;

      case 'session':
        if (!this.sessionStrategy.isAvailable()) {
          throw new StrategyNotAvailableException(
            'session',
            'Session strategy configuration missing or invalid',
          );
        }
        return this.sessionStrategy;

      default:
        throw new ConfigurationException(
          `Unknown authentication strategy: ${type}`,
        );
    }
  }

  /**
   * Get the default strategy based on module configuration
   * @returns Default authentication strategy
   */
  getDefaultStrategy(): IAuthStrategy {
    const strategyType = this.authOptions?.strategy || 'session';

    switch (strategyType) {
      case 'jwt':
        return this.createStrategy('jwt');

      case 'session':
        return this.createStrategy('session');

      case 'hybrid':
        // For hybrid mode, prefer session as default
        // But allow both strategies to be available
        if (this.sessionStrategy.isAvailable()) {
          return this.sessionStrategy;
        } else if (this.jwtStrategy.isAvailable()) {
          return this.jwtStrategy;
        } else {
          throw new Error('No authentication strategy is available');
        }

      default:
        throw new Error(
          `Unknown authentication strategy configuration: ${strategyType}`,
        );
    }
  }

  /**
   * Get strategy by auto-detection from request
   * @param request - HTTP request object
   * @returns Appropriate strategy or null if none detected
   */
  getStrategyFromRequest(request: any): IAuthStrategy | null {
    const hasJwtToken = this.detectJwtToken(request);
    const hasSessionId = this.detectSessionId(request);

    if (hasJwtToken && this.jwtStrategy.isAvailable()) {
      return this.jwtStrategy;
    }

    if (hasSessionId && this.sessionStrategy.isAvailable()) {
      return this.sessionStrategy;
    }

    return null;
  }

  /**
   * Get all available strategies
   * @returns Array of available strategy names
   */
  getAvailableStrategies(): string[] {
    const strategies: string[] = [];

    if (this.jwtStrategy.isAvailable()) {
      strategies.push('jwt');
    }

    if (this.sessionStrategy.isAvailable()) {
      strategies.push('session');
    }

    return strategies;
  }

  /**
   * Check if hybrid mode is enabled
   * @returns True if both JWT and Session strategies are available
   */
  isHybridMode(): boolean {
    return (
      this.authOptions?.strategy === 'hybrid' &&
      this.jwtStrategy.isAvailable() &&
      this.sessionStrategy.isAvailable()
    );
  }

  // Private helper methods

  private detectJwtToken(request: any): boolean {
    // Get configured cookie name for access token
    const accessTokenCookieName =
      this.authOptions?.cookies?.names?.accessToken || 'access-token';

    // Check cookies using configured name
    if (request.cookies && request.cookies[accessTokenCookieName]) {
      return true;
    }

    // Check Authorization header
    const authHeader = request.headers?.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      return true;
    }

    return false;
  }

  private detectSessionId(request: any): boolean {
    // Use session name from session config for consistency, fallback to cookie config, then default
    // Use session name exactly as configured, from environment, or default
    const sessionName =
      this.authOptions?.session?.name ||
      process.env.SESSION_NAME ||
      'sessionId';

    // Check cookies
    if (request.cookies && request.cookies[sessionName]) {
      return true;
    }

    // Check Authorization header with Session prefix
    const authHeader = request.headers?.authorization;
    if (authHeader && authHeader.startsWith('Session ')) {
      return true;
    }

    // Check custom header
    const sessionHeader = request.headers?.['x-session-id'];
    if (sessionHeader) {
      return true;
    }

    return false;
  }
}
