import { Injectable, Inject, Optional } from '@nestjs/common';
import { Request } from 'express';
import { AuthService } from './auth.service';
import { DeviceDetectionService } from '../device-detection.service';
import {
  IAuthStrategy,
  AuthSessionInfo,
  PasswordChangePolicy,
  AuthStats,
} from '../../interfaces/auth-strategy.interface';
import {
  IUser,
  UnifiedAuthResult,
  UnifiedAuthInput,
} from '../../interfaces/user.interface';
import { AuthModuleOptions } from '../../modules/auth.module';
import { getClientIp } from '../../utils/index';

/**
 * JWT Authentication Strategy Service
 * Implements IAuthStrategy interface for JWT-based authentication
 * Handles token generation, validation, and management
 */
@Injectable()
export class JwtStrategyService implements IAuthStrategy {
  constructor(
    private readonly authService: AuthService,
    private readonly deviceDetectionService: DeviceDetectionService,
    @Optional()
    @Inject('AUTH_MODULE_OPTIONS')
    private readonly authOptions?: AuthModuleOptions,
  ) {}

  /**
   * Login with JWT token generation
   */
  async login(
    input: UnifiedAuthInput,
    request: Request,
  ): Promise<UnifiedAuthResult> {
    try {
      this.deviceDetectionService.extractDeviceInfo(
        request.headers['user-agent'] || '',
        getClientIp(request),
      );

      const payload = {
        ...input.userData,
      };

      const token = this.authService.generateAccessToken(payload);
      const refreshToken = this.authService.generateRefreshToken(payload);

      return {
        user: input.userData,
        authenticated: true,
        authMethod: 'jwt',
        timestamp: new Date(),
        token,
        refreshToken,
      };
    } catch (error) {
      throw new Error(`JWT login failed: ${error.message}`);
    }
  }

  /**
   * Validate JWT token from request
   */
  async validateAuth(request: Request): Promise<UnifiedAuthResult | null> {
    try {
      const token = this.extractJwtToken(request);
      if (!token) return null;

      // Check if token is revoked
      const isRevoked = await this.authService.isTokenRevoked(token);
      if (isRevoked) return null;

      const payload = this.authService.verify(token);
      if (!payload) return null;

      // Convert payload back to IUser format

      const expiresAt = payload.exp ? new Date(payload.exp * 1000) : undefined;
      const issuedAt = payload.iat ? new Date(payload.iat * 1000) : undefined;

      return {
        user: payload as IUser,
        authenticated: true,
        authMethod: 'jwt',
        timestamp: new Date(),
        token,
        tokenInfo: {
          expiresAt,
          issuedAt,
        },
      };
    } catch (error) {
      return null;
    }
  }

  /**
   * Logout by revoking JWT token
   */
  async logout(
    request: Request,
  ): Promise<{ success: boolean; message?: string }> {
    try {
      const token = this.extractJwtToken(request);
      if (!token) {
        return { success: false, message: 'No JWT token found' };
      }

      const success = await this.authService.revokeToken(token);
      return {
        success,
        message: success
          ? 'JWT token revoked successfully'
          : 'Failed to revoke JWT token',
      };
    } catch (error) {
      return { success: false, message: `Logout failed: ${error.message}` };
    }
  }

  /**
   * Get user from JWT token
   */
  async getUser(request: Request): Promise<IUser | null> {
    const authResult = await this.validateAuth(request);
    return authResult?.user || null;
  }

  /**
   * Refresh JWT token
   */
  async refresh(request: Request): Promise<UnifiedAuthResult | null> {
    try {
      // Get configured cookie name for refresh token
      const refreshTokenCookieName =
        this.authOptions?.cookies?.names?.refreshToken || 'refresh-token';

      const refreshToken =
        request.cookies?.[refreshTokenCookieName] ||
        (request.headers['x-refresh-token'] as string);

      if (!refreshToken) return null;

      const payload = this.authService.verify(refreshToken);
      if (!payload) return null;

      const newToken = this.authService.generateAccessToken(payload);

      const decoded = this.authService.decode(newToken);
      const user: IUser = payload;

      return {
        user,
        authenticated: true,
        authMethod: 'jwt',
        timestamp: new Date(),
        token: newToken,
        tokenInfo: {
          expiresAt: decoded?.exp ? new Date(decoded.exp * 1000) : undefined,
          issuedAt: new Date(),
        },
      };
    } catch (error) {
      return null;
    }
  }

  async getUserSessions(userId: number): Promise<AuthSessionInfo[]> {
    return [];
  }

  /**
   * Invalidate all user sessions (revoke all tokens for user)
   */
  async invalidateAllUserSessions(userId: number): Promise<number> {
    // JWT is stateless, no sessions to invalidate
    return 0;
  }

  /**
   * Invalidate other sessions (keep current token)
   */
  async invalidateOtherSessions(
    userId: number,
    currentToken: string,
  ): Promise<number> {
    // JWT is stateless, no sessions to invalidate
    return 0;
  }

  /**
   * Handle password change (revoke tokens based on policy)
   */
  async handlePasswordChange(
    userId: number,
    policy: PasswordChangePolicy,
    currentToken?: string,
  ): Promise<number> {
    try {
      switch (policy) {
        case PasswordChangePolicy.INVALIDATE_ALL:
          return await this.invalidateAllUserSessions(userId);

        case PasswordChangePolicy.INVALIDATE_OTHERS:
          if (currentToken) {
            return await this.invalidateOtherSessions(userId, currentToken);
          } else {
            return await this.invalidateAllUserSessions(userId);
          }

        case PasswordChangePolicy.KEEP_ALL:
          return 0;

        default:
          return currentToken
            ? await this.invalidateOtherSessions(userId, currentToken)
            : await this.invalidateAllUserSessions(userId);
      }
    } catch (error) {
      return 0;
    }
  }

  /**
   * Get JWT authentication statistics
   */
  getStats(): AuthStats {
    return {
      strategyType: 'jwt',
      totalActive: 0, // JWT is stateless, can't track active tokens without additional storage
      totalUsers: 0,
      storageType: 'redis', // For revoked tokens storage
      connected: this.authService ? true : false,
    };
  }

  /**
   * Check if JWT strategy is available
   */
  isAvailable(): boolean {
    return (
      this.authService !== null && this.authOptions?.jwt?.secret !== undefined
    );
  }

  // Private utility methods

  private extractJwtToken(request: Request): string | null {
    // Get configured cookie name for access token
    const accessTokenCookieName =
      this.authOptions?.cookies?.names?.accessToken || 'access-token';

    // Check cookies first using configured name
    if (request.cookies?.[accessTokenCookieName]) {
      return request.cookies[accessTokenCookieName];
    }

    // Check Authorization header
    const authHeader = request.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      return authHeader.substring(7);
    }

    return null;
  }
}
