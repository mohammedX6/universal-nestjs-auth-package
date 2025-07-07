import { Injectable, Inject, Optional } from '@nestjs/common';
import { Request } from 'express';
import { SessionService } from './session.service';
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
import { PasswordChangeSessionPolicy } from '../../interfaces/session.interface';
import { getClientIp, extractSessionId } from '../../utils/index';

/**
 * Session Authentication Strategy Service
 * Implements IAuthStrategy interface for session-based authentication
 * Handles session creation, validation, and management with Redis storage
 */
@Injectable()
export class SessionStrategyService implements IAuthStrategy {
  constructor(
    private readonly sessionService: SessionService,
    private readonly deviceDetectionService: DeviceDetectionService,
    @Optional()
    @Inject('AUTH_MODULE_OPTIONS')
    private readonly authOptions?: AuthModuleOptions,
  ) {}

  /**
   * Login with session creation
   */
  async login(
    input: UnifiedAuthInput,
    request: Request,
  ): Promise<UnifiedAuthResult> {
    try {
      const deviceInfo = this.deviceDetectionService.extractDeviceInfo(
        request.headers['user-agent'] || '',
        getClientIp(request),
      );

      const sessionTimeout = input.options?.maxAge || 24 * 60 * 60 * 1000; // 24 hours

      const session = await this.sessionService.createSession(
        input.userData.userId,
        input.userData,
        deviceInfo,
        {
          sessionTimeout,
          metadata: input.options?.metadata,
        },
      );

      return {
        user: input.userData,
        authenticated: true,
        authMethod: 'session',
        timestamp: new Date(),
        sessionId: session.sessionId,
      };
    } catch (error) {
      throw new Error(`Session login failed: ${error.message}`);
    }
  }

  /**
   * Validate session from request
   */
  async validateAuth(request: Request): Promise<UnifiedAuthResult | null> {
    try {
      const sessionId = this.extractSessionId(request);
      if (!sessionId) return null;

      const validation = await this.sessionService.validateSession(sessionId);
      if (!validation.isValid || !validation.user) return null;

      return {
        user: validation.user,
        authenticated: true,
        authMethod: 'session',
        timestamp: new Date(),
        sessionId,
      };
    } catch (error) {
      return null;
    }
  }

  /**
   * Logout by destroying session
   */
  async logout(
    request: Request,
  ): Promise<{ success: boolean; message?: string }> {
    try {
      const sessionId = this.extractSessionId(request);
      if (!sessionId) {
        return { success: false, message: 'No session ID found' };
      }

      const success = await this.sessionService.destroySession(sessionId);
      return {
        success,
        message: success
          ? 'Session destroyed successfully'
          : 'Failed to destroy session',
      };
    } catch (error) {
      return { success: false, message: `Logout failed: ${error.message}` };
    }
  }

  /**
   * Get user from session
   */
  async getUser(request: Request): Promise<IUser | null> {
    const authResult = await this.validateAuth(request);
    return authResult?.user || null;
  }

  /**
   * Refresh session (extend session if needed)
   */
  async refresh(request: Request): Promise<UnifiedAuthResult | null> {
    try {
      // For sessions, just validate and extend if needed
      return await this.validateAuth(request);
    } catch (error) {
      return null;
    }
  }

  /**
   * Get all active sessions for a user
   */
  async getUserSessions(userId: number): Promise<AuthSessionInfo[]> {
    try {
      const sessions = await this.sessionService.getUserSessions(userId);

      return sessions.map((session) => ({
        id: session.sessionId,
        userId: session.userId,
        createdAt: session.createdAt,
        lastActivity: session.lastActivity,
        expiresAt: session.expiresAt,
        isActive: session.isActive,
        deviceInfo: {
          userAgent: session.deviceInfo.userAgent,
          ip: session.deviceInfo.ip,
          deviceType: session.deviceInfo.deviceType,
          browser: session.deviceInfo.browser,
          os: session.deviceInfo.os,
        },
        metadata: session.metadata,
      }));
    } catch (error) {
      return [];
    }
  }

  /**
   * Update user data across all active sessions
   * @param userId - User ID whose sessions to update
   * @param updateData - Partial user data to update in sessions
   * @returns Number of sessions successfully updated
   */
  async updateAllUserSessionsData(
    userId: number,
    updateData: Partial<IUser>,
  ): Promise<number> {
    try {
      return await this.sessionService.updateAllUserSessionsData(
        userId,
        updateData,
      );
    } catch (error) {
      return 0;
    }
  }

  /**
   * Update specific fields across all active user sessions
   * @param userId - User ID whose sessions to update
   * @param fieldUpdates - Object with field names and new values
   * @returns Number of sessions successfully updated
   */
  async updateUserSessionsFields(
    userId: number,
    fieldUpdates: Record<string, any>,
  ): Promise<number> {
    try {
      return await this.sessionService.updateUserSessionsFields(
        userId,
        fieldUpdates,
      );
    } catch (error) {
      return 0;
    }
  }

  /**
   * Invalidate all sessions for a user
   */
  async invalidateAllUserSessions(userId: number): Promise<number> {
    try {
      return await this.sessionService.invalidateAllUserSessions(userId);
    } catch (error) {
      return 0;
    }
  }

  /**
   * Invalidate other sessions (keep current one)
   */
  async invalidateOtherSessions(
    userId: number,
    currentSessionId: string,
  ): Promise<number> {
    try {
      return await this.sessionService.invalidateOtherSessions(
        userId,
        currentSessionId,
      );
    } catch (error) {
      return 0;
    }
  }

  /**
   * Handle password change session invalidation
   */
  async handlePasswordChange(
    userId: number,
    policy: PasswordChangePolicy,
    currentSessionId?: string,
  ): Promise<number> {
    try {
      // Map our policy to session service policy
      let sessionPolicy: PasswordChangeSessionPolicy;
      switch (policy) {
        case PasswordChangePolicy.INVALIDATE_ALL:
          sessionPolicy = PasswordChangeSessionPolicy.INVALIDATE_ALL;
          break;
        case PasswordChangePolicy.INVALIDATE_OTHERS:
          sessionPolicy = PasswordChangeSessionPolicy.INVALIDATE_OTHERS;
          break;
        case PasswordChangePolicy.KEEP_ALL:
          sessionPolicy = PasswordChangeSessionPolicy.KEEP_ALL;
          break;
        default:
          sessionPolicy = PasswordChangeSessionPolicy.INVALIDATE_OTHERS;
      }

      return await this.sessionService.handlePasswordChangeSessionInvalidation(
        userId,
        sessionPolicy,
        currentSessionId,
      );
    } catch (error) {
      return 0;
    }
  }

  /**
   * Check if session strategy is available
   */
  isAvailable(): boolean {
    return (
      this.sessionService !== null &&
      this.authOptions?.session?.secret !== undefined
    );
  }

  // Private utility methods

  private extractSessionId(request: Request): string | null {
    // Use the centralized utility function with configured session name
    const sessionName =
      this.authOptions?.session?.name ||
      process.env.SESSION_NAME ||
      'sessionId';
    return extractSessionId(request, sessionName);
  }
}
