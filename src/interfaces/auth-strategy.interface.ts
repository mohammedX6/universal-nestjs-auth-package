import { Request } from 'express';
import { UnifiedAuthResult, UnifiedAuthInput } from './user.interface';

/**
 * Unified Authentication Strategy Interface
 * Defines all methods that both JWT and Session services must implement
 * Provides consistent API regardless of authentication method
 */
export interface IAuthStrategy {
  /**
   * Authenticate user and create authentication token/session
   * @param input - Unified authentication input
   * @param request - HTTP request object
   * @returns Unified authentication result
   */
  login(input: UnifiedAuthInput, request: Request): Promise<UnifiedAuthResult>;

  /**
   * Validate authentication from request
   * @param request - HTTP request object
   * @returns Unified authentication result or null if invalid
   */
  validateAuth(request: Request): Promise<UnifiedAuthResult | null>;

  /**
   * Logout user and invalidate authentication
   * @param request - HTTP request object
   * @returns Success status
   */
  logout(request: Request): Promise<{ success: boolean; message?: string }>;

  /**
   * Get user information from request
   * @param request - HTTP request object
   * @returns User data or null
   */
  getUser(request: Request): Promise<any | null>;

  /**
   * Refresh authentication if supported
   * @param request - HTTP request object
   * @returns New authentication result or null
   */
  refresh(request: Request): Promise<UnifiedAuthResult | null>;

  /**
   * Get all active sessions/tokens for a user
   * @param userId - User ID
   * @returns Array of session/token information
   */
  getUserSessions(userId: number): Promise<any[]>;

  /**
   * Invalidate all sessions/tokens for a user
   * @param userId - User ID
   * @returns Number of invalidated sessions/tokens
   */
  invalidateAllUserSessions(userId: number): Promise<number>;

  /**
   * Invalidate other sessions/tokens (keep current one)
   * @param userId - User ID
   * @param currentIdentifier - Current session ID or token
   * @returns Number of invalidated sessions/tokens
   */
  invalidateOtherSessions(
    userId: number,
    currentIdentifier: string,
  ): Promise<number>;

  /**
   * Handle password change session invalidation
   * @param userId - User ID
   * @param policy - Invalidation policy
   * @param currentIdentifier - Current session ID or token
   * @returns Number of invalidated sessions/tokens
   */
  handlePasswordChange(
    userId: number,
    policy: PasswordChangePolicy,
    currentIdentifier?: string,
  ): Promise<number>;

  /**
   * Check if authentication method is available
   * @returns True if the strategy is ready to use
   */
  isAvailable(): boolean;
}

/**
 * Authentication session/token information
 */
export interface AuthSessionInfo {
  id: string;
  userId: number;
  createdAt: Date;
  lastActivity: Date;
  expiresAt: Date;
  isActive: boolean;
  deviceInfo?: {
    userAgent: string;
    ip: string;
    deviceType: string;
    browser?: string;
    os?: string;
  };
  metadata?: Record<string, any>;
}

/**
 * Password change session invalidation policy
 */
export enum PasswordChangePolicy {
  INVALIDATE_ALL = 'invalidate_all',
  INVALIDATE_OTHERS = 'invalidate_others',
  KEEP_ALL = 'keep_all',
}

/**
 * Authentication statistics
 */
export interface AuthStats {
  strategyType: 'jwt' | 'session';
  totalActive: number;
  totalUsers: number;
  storageType?: string;
  connected?: boolean;
  lastCleanup?: Date;
}

/**
 * Authentication strategy factory interface
 */
export interface IAuthStrategyFactory {
  createStrategy(type: 'jwt' | 'session'): IAuthStrategy;
  getAvailableStrategies(): string[];
}
