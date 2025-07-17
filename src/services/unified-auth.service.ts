import { Injectable, Inject, Optional } from '@nestjs/common';
import { Request } from 'express';
import { JwtSignOptions } from '@nestjs/jwt';
import { AuthStrategyFactory } from './auth-strategy.factory';
import { AuthService } from './jwt/auth.service';
import {
  IUser,
  UnifiedAuthResult,
  UnifiedAuthInput,
} from '../interfaces/user.interface';
import { AuthModuleOptions } from '../modules/auth.module';
import {
  AuthSessionInfo,
  PasswordChangePolicy,
} from '../interfaces/auth-strategy.interface';
import {
  AuthenticationFailedException,
  StrategyNotAvailableException,
  ValidationException,
} from '../exceptions/auth.exceptions';

/**
 * Unified Authentication Service
 * Uses strategy pattern to provide the same interface for both JWT and Session authentication
 * Always returns IUser interface regardless of auth method
 * No changes needed in microservices - just use this service
 */
@Injectable()
export class UnifiedAuthService {
  constructor(
    private readonly strategyFactory: AuthStrategyFactory,
    private readonly authService: AuthService,
    @Optional()
    @Inject('AUTH_MODULE_OPTIONS')
    private readonly authOptions?: AuthModuleOptions,
  ) {}

  // JWT Token Methods - delegated to AuthService
  /**
   * Sign JWT token
   * @param payload - Token payload
   * @param options - JWT sign options
   * @returns Signed JWT token
   */
  sign(payload: any, options: JwtSignOptions = {}): string {
    return this.authService.sign(payload, options);
  }

  /**
   * Verify JWT token
   * @param token - JWT token to verify
   * @returns Decoded token payload
   */
  verify(token: string): any {
    return this.authService.verify(token);
  }

  /**
   * Decode JWT token without verification
   * @param token - JWT token to decode
   * @returns Decoded token payload
   */
  decode(token: string): any {
    return this.authService.decode(token);
  }

  /**
   * Revoke a token by storing it in Redis with TTL
   * @param token - Token to revoke
   * @param ttl - Time to live in seconds (optional)
   * @returns Success status
   */
  async revokeToken(token: string, ttl?: number): Promise<boolean> {
    return this.authService.revokeToken(token, ttl);
  }

  /**
   * Check if token is revoked
   * @param token - Token to check
   * @returns True if token is revoked
   */
  async isTokenRevoked(token: string): Promise<boolean> {
    return this.authService.isTokenRevoked(token);
  }

  /**
   * Generate access token
   * @param payload - Token payload
   * @returns Access token
   */
  generateAccessToken(payload: any): string {
    return this.authService.generateAccessToken(payload);
  }

  /**
   * Generate refresh token
   * @param payload - Token payload
   * @returns Refresh token
   */
  generateRefreshToken(payload: any): string {
    return this.authService.generateRefreshToken(payload);
  }

  /**
   * Generate token pair (access + refresh)
   * @param payload - Token payload
   * @returns Object containing access and refresh tokens
   */
  generateTokenPair(payload: any): {
    accessToken: string;
    refreshToken: string;
  } {
    return this.authService.generateTokenPair(payload);
  }

  /**
   * Unified Login - same input/output for both JWT and Session
   * @param input - Unified authentication input
   * @param request - HTTP request object
   * @returns Unified authentication result with IUser
   */
  async login(
    input: UnifiedAuthInput,
    request: Request,
  ): Promise<UnifiedAuthResult> {
    try {
      // Validate input
      if (!input.userData) {
        throw new ValidationException(
          'User data is required for authentication',
        );
      }
      const strategy = this.getStrategyForLogin(input);
      const result = await strategy.login(input, request);

      return result;
    } catch (error) {
      if (
        error instanceof ValidationException ||
        error instanceof StrategyNotAvailableException
      ) {
        throw error;
      }

      throw new AuthenticationFailedException(
        `Authentication failed: ${error.message}`,
      );
    }
  }

  /**
   * Unified Validation - same input/output for both JWT and Session
   * @param request - HTTP request object
   * @returns Unified authentication result with IUser
   */
  async validateAuth(request: Request): Promise<UnifiedAuthResult | null> {
    try {
      // Try to auto-detect strategy from request
      const strategy = this.strategyFactory.getStrategyFromRequest(request);
      if (strategy) {
        return await strategy.validateAuth(request);
      }

      // If no strategy detected, try default strategy
      const defaultStrategy = this.strategyFactory.getDefaultStrategy();
      return await defaultStrategy.validateAuth(request);
    } catch (error) {
      return null;
    }
  }

  /**
   * Unified Logout - works with both JWT and Session
   * @param request - HTTP request object
   * @returns Success status
   */
  async logout(
    request: Request,
  ): Promise<{ success: boolean; method: string[] }> {
    const methods: string[] = [];
    let success = false;

    try {
      // Try to logout from all available strategies
      const availableStrategies = this.strategyFactory.getAvailableStrategies();

      for (const strategyType of availableStrategies) {
        try {
          const strategy = this.strategyFactory.createStrategy(
            strategyType as 'jwt' | 'session',
          );
          const result = await strategy.logout(request);

          if (result.success) {
            methods.push(strategyType);
            success = true;
          }
        } catch (error) {
          // Continue with other strategies
        }
      }

      return { success, method: methods };
    } catch (error) {
      return { success: false, method: [] };
    }
  }

  /**
   * Get user information - same output regardless of auth method
   * @param request - HTTP request object
   * @returns IUser or null
   */
  async getUser(request: Request): Promise<IUser | null> {
    const authResult = await this.validateAuth(request);
    return authResult?.user || null;
  }

  /**
   * Refresh authentication - works with both methods
   * @param request - HTTP request object
   * @returns New authentication result or null
   */
  async refresh(request: Request): Promise<UnifiedAuthResult | null> {
    try {
      const strategy = this.strategyFactory.getStrategyFromRequest(request);
      if (strategy) {
        return await strategy.refresh(request);
      }

      return null;
    } catch (error) {
      return null;
    }
  }

  /**
   * Get all active sessions/tokens for a user
   * @param userId - User ID
   * @param strategyType - Optional strategy type, defaults to auto-detect
   * @returns Array of session/token information
   */
  async getUserSessions(
    userId: number,
    strategyType?: 'jwt' | 'session',
  ): Promise<any[]> {
    try {
      if (strategyType) {
        const strategy = this.strategyFactory.createStrategy(strategyType);
        return await strategy.getUserSessions(userId);
      }

      // Get sessions from all available strategies
      const allSessions: AuthSessionInfo[] = [];
      const availableStrategies = this.strategyFactory.getAvailableStrategies();

      for (const type of availableStrategies) {
        try {
          const strategy = this.strategyFactory.createStrategy(
            type as 'jwt' | 'session',
          );
          const sessions = await strategy.getUserSessions(userId);
          allSessions.push(...sessions);
        } catch (error) {
          // Continue with other strategies
        }
      }

      return allSessions;
    } catch (error) {
      return [];
    }
  }

  /**
   * Update user data across all active sessions
   * Only applies to session-based authentication
   * @param userId - User ID whose sessions to update
   * @param updateData - Partial user data to update in sessions
   * @returns Number of sessions successfully updated
   */
  async updateAllUserSessionsData(
    userId: number,
    updateData: Partial<IUser>,
  ): Promise<number> {
    try {
      // Only session strategy supports updating user data
      const availableStrategies = this.strategyFactory.getAvailableStrategies();

      if (availableStrategies.includes('session')) {
        const sessionStrategy = this.strategyFactory.createStrategy('session');
        if ('updateAllUserSessionsData' in sessionStrategy) {
          return await (sessionStrategy as any).updateAllUserSessionsData(
            userId,
            updateData,
          );
        }
      }

      return 0;
    } catch (error) {
      return 0;
    }
  }

  /**
   * Update specific fields across all active user sessions
   * Only applies to session-based authentication
   * @param userId - User ID whose sessions to update
   * @param fieldUpdates - Object with field names and new values
   * @returns Number of sessions successfully updated
   */
  async updateUserSessionsFields(
    userId: number,
    fieldUpdates: Record<string, any>,
  ): Promise<number> {
    try {
      // Only session strategy supports updating user data
      const availableStrategies = this.strategyFactory.getAvailableStrategies();

      if (availableStrategies.includes('session')) {
        const sessionStrategy = this.strategyFactory.createStrategy('session');
        if ('updateUserSessionsFields' in sessionStrategy) {
          return await (sessionStrategy as any).updateUserSessionsFields(
            userId,
            fieldUpdates,
          );
        }
      }

      return 0;
    } catch (error) {
      return 0;
    }
  }

  /**
   * Invalidate all sessions/tokens for a user
   * @param userId - User ID
   * @param strategyType - Optional strategy type, defaults to all
   * @returns Number of invalidated sessions/tokens
   */
  async invalidateAllUserSessions(
    userId: number,
    strategyType?: 'jwt' | 'session',
  ): Promise<number> {
    try {
      if (strategyType) {
        const strategy = this.strategyFactory.createStrategy(strategyType);
        return await strategy.invalidateAllUserSessions(userId);
      }

      // Invalidate sessions from all available strategies
      let totalInvalidated = 0;
      const availableStrategies = this.strategyFactory.getAvailableStrategies();

      for (const type of availableStrategies) {
        try {
          const strategy = this.strategyFactory.createStrategy(
            type as 'jwt' | 'session',
          );
          const invalidated = await strategy.invalidateAllUserSessions(userId);
          totalInvalidated += invalidated;
        } catch (error) {
          // Continue with other strategies
        }
      }

      return totalInvalidated;
    } catch (error) {
      return 0;
    }
  }

  /**
   * Invalidate other sessions/tokens (keep current one)
   * @param userId - User ID
   * @param currentIdentifier - Current session ID or token
   * @param strategyType - Optional strategy type, defaults to auto-detect
   * @returns Number of invalidated sessions/tokens
   */
  async invalidateOtherSessions(
    userId: number,
    currentIdentifier: string,
    strategyType?: 'jwt' | 'session',
  ): Promise<number> {
    try {
      if (strategyType) {
        const strategy = this.strategyFactory.createStrategy(strategyType);
        return await strategy.invalidateOtherSessions(
          userId,
          currentIdentifier,
        );
      }

      // Invalidate from all available strategies
      let totalInvalidated = 0;
      const availableStrategies = this.strategyFactory.getAvailableStrategies();

      for (const type of availableStrategies) {
        try {
          const strategy = this.strategyFactory.createStrategy(
            type as 'jwt' | 'session',
          );
          const invalidated = await strategy.invalidateOtherSessions(
            userId,
            currentIdentifier,
          );
          totalInvalidated += invalidated;
        } catch (error) {
          // Continue with other strategies
        }
      }

      return totalInvalidated;
    } catch (error) {
      return 0;
    }
  }

  /**
   * Handle password change session invalidation
   * @param userId - User ID
   * @param policy - Invalidation policy
   * @param currentIdentifier - Current session ID or token
   * @param strategyType - Optional strategy type, defaults to all
   * @returns Number of invalidated sessions/tokens
   */
  async handlePasswordChange(
    userId: number,
    policy: PasswordChangePolicy,
    currentIdentifier?: string,
    strategyType?: 'jwt' | 'session',
  ): Promise<number> {
    try {
      if (strategyType) {
        const strategy = this.strategyFactory.createStrategy(strategyType);
        return await strategy.handlePasswordChange(
          userId,
          policy,
          currentIdentifier,
        );
      }

      // Handle password change for all available strategies
      let totalInvalidated = 0;
      const availableStrategies = this.strategyFactory.getAvailableStrategies();

      for (const type of availableStrategies) {
        try {
          const strategy = this.strategyFactory.createStrategy(
            type as 'jwt' | 'session',
          );
          const invalidated = await strategy.handlePasswordChange(
            userId,
            policy,
            currentIdentifier,
          );
          totalInvalidated += invalidated;
        } catch (error) {
          // Continue with other strategies
        }
      }

      return totalInvalidated;
    } catch (error) {
      return 0;
    }
  }

  /**
   * Check if authentication service is available
   * @returns True if at least one strategy is available
   */
  isAvailable(): boolean {
    return this.strategyFactory.getAvailableStrategies().length > 0;
  }

  // Private helper methods

  private getStrategyForLogin(input: UnifiedAuthInput) {
    const authMethod = input.authMethod || 'auto';

    switch (authMethod) {
      case 'jwt':
        return this.strategyFactory.createStrategy('jwt');

      case 'session':
        return this.strategyFactory.createStrategy('session');

      case 'auto':
      default:
        return this.strategyFactory.getDefaultStrategy();
    }
  }
}
