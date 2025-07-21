import {
  Injectable,
  Logger,
  OnModuleInit,
  OnModuleDestroy,
  Inject,
  Optional,
} from '@nestjs/common';
import { createClient, RedisClientType } from 'redis';
import {
  UserSession,
  DeviceInfo,
  SessionValidationResult,
  SessionCreateOptions,
  PasswordChangeSessionPolicy,
} from '../../interfaces/session.interface';
import { IUser } from '../../interfaces/user.interface';
import { SessionModuleOptions } from '../../modules/session.module';
import { generateSecureSessionId } from '../../utils';
import { SessionState, DeviceType } from '../../types/auth.types';
import * as crypto from 'crypto';

/**
 * Enhanced session management service with Redis storage
 * Uses IUser interface for consistent data structure
 * Now properly receives configuration from forRoot method
 * Uses cryptographically secure session ID generation
 * Uses proper auth types for type safety
 */
@Injectable()
export class SessionService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(SessionService.name);
  private redisClient: RedisClientType | null = null;
  private readonly config: any;
  private readonly redisConfig: any;
  private isConnected = false;
  private reconnectAttempts = 0;
  private readonly maxReconnectAttempts = 5;

  constructor(
    @Optional()
    @Inject('SESSION_MODULE_OPTIONS')
    private readonly sessionOptions?: SessionModuleOptions,
  ) {
    // Use configuration from forRoot if available, otherwise fall back to process.env
    this.config = {
      maxSessionsPerUser:
        this.sessionOptions?.multiSession?.maxSessions ||
        parseInt(process.env.MAX_SESSIONS_PER_USER || '5'),
      // Session timeout in milliseconds - everything in milliseconds for consistency
      sessionTimeoutMs:
        this.sessionOptions?.maxAge ||
        parseInt(process.env.SESSION_MAX_AGE || '86400') * 1000, // Convert env seconds to milliseconds
      sessionTimeoutRememberMeMs:
        this.sessionOptions?.maxAgeRememberMe ||
        parseInt(process.env.SESSION_MAX_AGE_REMEMBER_ME || '86400') * 1000, // Convert env seconds to milliseconds
      extendOnActivity: true,
      cleanupInterval:
        parseInt(process.env.SESSION_CLEANUP_INTERVAL || '3600') * 1000, // Convert to milliseconds
      deviceTrackingEnabled: true,
      // Session ID security configuration
      sessionIdLength: parseInt(process.env.SESSION_ID_LENGTH || '32'), // 32 bytes = 256 bits of entropy
    };

    // Use Redis configuration from forRoot if available, otherwise fall back to process.env
    this.redisConfig = {
      host:
        this.sessionOptions?.redis?.host ||
        process.env.REDIS_HOST ||
        'localhost',
      port:
        this.sessionOptions?.redis?.port ||
        parseInt(process.env.REDIS_PORT || '6379'),
      password:
        this.sessionOptions?.redis?.password || process.env.REDIS_PASSWORD,
      db:
        this.sessionOptions?.redis?.db !== undefined
          ? this.sessionOptions?.redis?.db
          : parseInt(process.env.REDIS_SESSION_DB || '0'),
      keyPrefix: this.getSessionKeyPrefix(),
    };

    this.logger.log('SessionService initialized with configuration:', {
      redis: {
        host: this.redisConfig.host,
        port: this.redisConfig.port,
        db: this.redisConfig.db,
        hasPassword: !!this.redisConfig.password,
        ttlSeconds: this.redisConfig.ttl,
      },
      multiSession: {
        maxSessions: this.config.maxSessionsPerUser,
        sessionTimeoutMs: this.config.sessionTimeoutMs,
        sessionTimeoutHours:
          Math.round((this.config.sessionTimeoutMs / (1000 * 60 * 60)) * 100) /
          100,
      },
      security: {
        sessionIdLength: this.config.sessionIdLength,
      },
    });
  }

  /**
   * Initialize the service and Redis connection
   */
  async onModuleInit() {
    await this.initializeRedis();
  }

  /**
   * Clean up Redis connection on module destroy
   */
  async onModuleDestroy() {
    if (this.redisClient && this.isConnected) {
      try {
        await this.redisClient.quit();
        this.logger.log('Redis connection closed');
      } catch (error) {
        this.logger.error('Error closing Redis connection:', error);
      }
    }
  }

  /**
   * Initialize Redis connection with retry logic
   */
  private async initializeRedis(): Promise<void> {
    try {
      this.redisClient = createClient({
        url: `redis://${this.redisConfig.host}:${this.redisConfig.port}`,
        password: this.redisConfig.password,
        database: this.redisConfig.db,
        socket: {
          reconnectStrategy: (retries) => {
            if (retries > this.maxReconnectAttempts) {
              this.logger.error('Max Redis reconnection attempts reached');
              return false;
            }
            return Math.min(retries * 50, 500);
          },
        },
      });

      this.redisClient.on('error', (err) => {
        this.logger.error('Redis Session Error:', err);
        this.isConnected = false;
      });

      this.redisClient.on('connect', () => {
        this.logger.log('Redis Session Store Connected');
        this.isConnected = true;
        this.reconnectAttempts = 0;
      });

      this.redisClient.on('reconnecting', () => {
        this.reconnectAttempts++;
        this.logger.warn(
          `Redis reconnecting... Attempt ${this.reconnectAttempts}`,
        );
      });

      await this.redisClient.connect();
    } catch (error) {
      this.logger.error('Failed to initialize Redis:', error);
      this.isConnected = false;
    }
  }

  /**
   * Check if Redis is available
   */
  private isRedisAvailable(): boolean {
    return this.redisClient !== null && this.isConnected;
  }

  /**
   * Execute Redis operation with error handling
   */
  private async executeRedisOperation<T>(
    operation: () => Promise<T>,
  ): Promise<T | null> {
    if (!this.isRedisAvailable()) {
      this.logger.warn('Redis not available, operation skipped');
      return null;
    }

    try {
      return await operation();
    } catch (error) {
      this.logger.error('Redis operation failed:', error);
      this.isConnected = false;
      return null;
    }
  }

  /**
   * Create new user session with unified IUser interface
   */
  async createSession(
    userId: number,
    userData: IUser,
    deviceInfo: DeviceInfo,
    options: SessionCreateOptions = {},
  ): Promise<UserSession> {
    try {
      // Generate secure session ID with configured length
      const sessionId = generateSecureSessionId(this.config.sessionIdLength);

      // Check session limits before creating new session
      await this.enforceSessionLimits(userId, options.maxSessions);

      // Ensure device fingerprint is set
      if (!deviceInfo.fingerprint) {
        // Generate a simple fingerprint from available device info
        deviceInfo.fingerprint = this.generateDeviceFingerprint(deviceInfo);
      }

      // Create session object with IUser data and proper types
      const session: UserSession = {
        sessionId,
        userId,
        deviceInfo,
        userData,
        createdAt: new Date(),
        lastActivity: new Date(),
        expiresAt: new Date(
          Date.now() + (options.sessionTimeout || this.config.sessionTimeoutMs),
        ),
        isActive: true,
        state: 'active' as SessionState,
        metadata: options.metadata,
      };

      // Store session in Redis
      const stored = await this.storeSession(session);
      if (!stored) {
        throw new Error('Failed to store session in Redis');
      }

      // Add to user's session list
      await this.addToUserSessions(userId, sessionId);

      this.logger.log(`Session created for user ${userId}: ${sessionId}`);
      return session;
    } catch (error) {
      this.logger.error(`Failed to create session for user ${userId}:`, error);
      throw error;
    }
  }

  /**
   * Validate session by ID with unified return format and proper auth types
   */
  async validateSession(sessionId: string): Promise<SessionValidationResult> {
    try {
      if (!sessionId) {
        return {
          isValid: false,
          status: 'unauthenticated',
          error: 'No session ID provided',
        };
      }

      // Get session from Redis
      const session = await this.getSession(sessionId);

      if (!session) {
        return {
          isValid: false,
          status: 'invalid',
          error: 'Session not found',
        };
      }

      // Check if session is expired
      if (new Date() > session.expiresAt) {
        // Update session state before destroying
        session.state = 'expired' as SessionState;
        await this.destroySession(sessionId);
        return {
          isValid: false,
          status: 'expired',
          error: 'Session expired',
        };
      }

      // Check if session is active
      if (!session.isActive || session.state !== 'active') {
        return {
          isValid: false,
          status: 'invalid',
          error: 'Session inactive',
        };
      }

      // Update last activity if configured
      if (this.config.extendOnActivity) {
        await this.updateLastActivity(sessionId);
      }

      return {
        isValid: true,
        status: 'authenticated',
        session,
        user: session.userData,
      };
    } catch (error) {
      this.logger.error(`Session validation failed for ${sessionId}:`, error);
      return {
        isValid: false,
        status: 'invalid',
        error: error.message || 'Session validation failed',
      };
    }
  }

  /**
   * Get all active sessions for a user
   */
  async getUserSessions(userId: number): Promise<UserSession[]> {
    try {
      const sessionIds = await this.getUserSessionIds(userId);
      const sessions: UserSession[] = [];

      for (const sessionId of sessionIds) {
        const session = await this.getSession(sessionId);
        if (session && session.isActive && new Date() <= session.expiresAt) {
          sessions.push(session);
        }
      }

      return sessions;
    } catch (error) {
      this.logger.error(`Failed to get sessions for user ${userId}:`, error);
      return [];
    }
  }

  /**
   * Destroy a specific session with proper state management
   */
  async destroySession(sessionId: string): Promise<boolean> {
    if (!this.isRedisAvailable()) {
      this.logger.warn('Redis not available, cannot destroy session');
      return false;
    }

    try {
      const session = await this.getSession(sessionId);
      if (session) {
        // Update session state before destroying
        session.state = 'revoked' as SessionState;
        session.isActive = false;

        // Remove from user's session list first
        await this.removeFromUserSessions(session.userId, sessionId);

        // Remove session data
        const deleted = await this.executeRedisOperation(async () => {
          return this.redisClient!.del(this.getSessionKey(sessionId));
        });

        if (deleted) {
          this.logger.log(
            `Session destroyed: ${sessionId} for user ${session.userId}`,
          );
          return true;
        } else {
          this.logger.warn(`Failed to delete session data for: ${sessionId}`);
          return false;
        }
      } else {
        // Session doesn't exist, but we should still try to clean up any references
        this.logger.warn(`Session not found for destruction: ${sessionId}`);
        // Try to remove from Redis anyway in case it exists but couldn't be parsed
        await this.executeRedisOperation(async () => {
          return this.redisClient!.del(this.getSessionKey(sessionId));
        });
        return false;
      }
    } catch (error) {
      this.logger.error(`Failed to destroy session ${sessionId}:`, error);
      return false;
    }
  }

  /**
   * Update specific data for all active sessions of a user
   * Useful for propagating user data changes across all sessions
   * @param userId - User ID whose sessions to update
   * @param updateData - Partial user data to update in sessions
   * @returns Number of sessions successfully updated
   */
  async updateAllUserSessionsData(
    userId: number,
    updateData: Partial<IUser>,
  ): Promise<number> {
    try {
      const sessionIds = await this.getUserSessionIds(userId);
      let updatedCount = 0;

      for (const sessionId of sessionIds) {
        const session = await this.getSession(sessionId);
        if (session && session.isActive) {
          // Merge the update data with existing user data
          const updatedUserData = {
            ...session.userData,
            ...updateData,
          };

          // Update the session with new user data
          const updatedSession: UserSession = {
            ...session,
            userData: updatedUserData,
            lastActivity: new Date(), // Update last activity timestamp
          };

          const success = await this.storeSession(updatedSession);
          if (success) {
            updatedCount++;
          }
        }
      }

      this.logger.log(
        `Updated user data in ${updatedCount} sessions for user ${userId}`,
      );
      return updatedCount;
    } catch (error) {
      this.logger.error(
        `Failed to update session data for user ${userId}:`,
        error,
      );
      return 0;
    }
  }

  /**
   * Update specific fields for all active sessions of a user
   * More granular control over what gets updated
   * @param userId - User ID whose sessions to update
   * @param fieldUpdates - Object with field names and new values
   * @returns Number of sessions successfully updated
   */
  async updateUserSessionsFields(
    userId: number,
    fieldUpdates: Record<string, any>,
  ): Promise<number> {
    try {
      const sessionIds = await this.getUserSessionIds(userId);
      let updatedCount = 0;

      for (const sessionId of sessionIds) {
        const session = await this.getSession(sessionId);
        if (session && session.isActive) {
          // Create updated user data with specific field updates
          const updatedUserData = { ...session.userData };

          // Apply field updates
          Object.keys(fieldUpdates).forEach((field) => {
            if (field !== 'userId' && field !== 'id') {
              // Protect critical ID fields
              updatedUserData[field] = fieldUpdates[field];
            }
          });

          // Update the session with new user data
          const updatedSession: UserSession = {
            ...session,
            userData: updatedUserData,
            lastActivity: new Date(),
          };

          const success = await this.storeSession(updatedSession);
          if (success) {
            updatedCount++;
          }
        }
      }

      this.logger.log(
        `Updated fields in ${updatedCount} sessions for user ${userId}`,
        fieldUpdates,
      );
      return updatedCount;
    } catch (error) {
      this.logger.error(
        `Failed to update session fields for user ${userId}:`,
        error,
      );
      return 0;
    }
  }

  /**
   * Invalidate all sessions for a user
   */
  async invalidateAllUserSessions(userId: number): Promise<number> {
    try {
      const sessionIds = await this.getUserSessionIds(userId);
      let invalidated = 0;

      for (const sessionId of sessionIds) {
        const success = await this.destroySession(sessionId);
        if (success) invalidated++;
      }

      this.logger.log(`Invalidated ${invalidated} sessions for user ${userId}`);
      return invalidated;
    } catch (error) {
      this.logger.error(
        `Failed to invalidate sessions for user ${userId}:`,
        error,
      );
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
      const sessionIds = await this.getUserSessionIds(userId);
      let invalidated = 0;

      for (const sessionId of sessionIds) {
        if (sessionId !== currentSessionId) {
          const success = await this.destroySession(sessionId);
          if (success) invalidated++;
        }
      }

      this.logger.log(
        `Invalidated ${invalidated} other sessions for user ${userId}`,
      );
      return invalidated;
    } catch (error) {
      this.logger.error(
        `Failed to invalidate other sessions for user ${userId}:`,
        error,
      );
      return 0;
    }
  }

  /**
   * Handle password change session invalidation
   */
  async handlePasswordChangeSessionInvalidation(
    userId: number,
    policy: PasswordChangeSessionPolicy,
    currentSessionId?: string,
  ): Promise<number> {
    switch (policy) {
      case PasswordChangeSessionPolicy.INVALIDATE_ALL:
        return this.invalidateAllUserSessions(userId);

      case PasswordChangeSessionPolicy.INVALIDATE_OTHERS:
        if (currentSessionId) {
          return this.invalidateOtherSessions(userId, currentSessionId);
        } else {
          return this.invalidateAllUserSessions(userId);
        }

      case PasswordChangeSessionPolicy.KEEP_ALL:
        return 0;

      default:
        return currentSessionId
          ? this.invalidateOtherSessions(userId, currentSessionId)
          : this.invalidateAllUserSessions(userId);
    }
  }

  /**
   * Update specific fields for all active sessions of a user
   * More granular control over what gets updated
   * @param userId - User ID whose sessions to update
   * @param fieldUpdates - Object with field names and new values
   * @returns Number of sessions successfully updated
   */
  async updateSessionFields(
    sessionId: string,
    fieldUpdates: Record<string, any>,
  ): Promise<number> {
    try {
      let updatedCount = 0;

      const session = await this.getSession(sessionId);
      if (session && session.isActive) {
        // Create updated user data with specific field updates
        const updatedUserData = { ...session.userData };

        // Apply field updates
        Object.keys(fieldUpdates).forEach((field) => {
          if (field !== 'userId' && field !== 'id') {
            // Protect critical ID fields
            updatedUserData[field] = fieldUpdates[field];
          }
        });

        // Update the session with new user data
        const updatedSession: UserSession = {
          ...session,
          userData: updatedUserData,
          lastActivity: new Date(),
        };

        const success = await this.storeSession(updatedSession);
        if (success) {
          updatedCount++;
        }
      }

      this.logger.log(
        `Updated fields in ${updatedCount} sessions for session ${sessionId}`,
        fieldUpdates,
      );
      return updatedCount;
    } catch (error) {
      this.logger.error(
        `Failed to update session fields for user ${sessionId}:`,
        error,
      );
      return 0;
    }
  }

  // Private helper methods

  /**
   * Store session in Redis with error handling
   * TTL is set per-session based on the session's actual expiresAt value.
   * This ensures correct expiration for maxAge, remember me, etc.
   */
  private async storeSession(session: UserSession): Promise<boolean> {
    return (
      (await this.executeRedisOperation(async () => {
        // Calculate TTL in seconds based on session's expiresAt
        const ttlSeconds = Math.max(
          1,
          Math.floor((session.expiresAt.getTime() - Date.now()) / 1000),
        );
        await this.redisClient!.setEx(
          this.getSessionKey(session.sessionId),
          ttlSeconds,
          JSON.stringify(session),
        );
        return true;
      })) !== null
    );
  }

  /**
   * Get session from Redis with error handling
   */
  private async getSession(sessionId: string): Promise<UserSession | null> {
    return this.executeRedisOperation(async () => {
      const sessionData = await this.redisClient!.get(
        this.getSessionKey(sessionId),
      );
      if (!sessionData || typeof sessionData !== 'string') {
        return null;
      }

      const session = JSON.parse(sessionData);
      // Convert date strings back to Date objects
      session.createdAt = new Date(session.createdAt);
      session.lastActivity = new Date(session.lastActivity);
      session.expiresAt = new Date(session.expiresAt);

      return session;
    });
  }

  /**
   * Update last activity timestamp
   */
  private async updateLastActivity(sessionId: string): Promise<void> {
    await this.executeRedisOperation(async () => {
      const session = await this.getSession(sessionId);
      if (session) {
        session.lastActivity = new Date();
        // Also extend session expiration if configured
        if (this.config.extendOnActivity) {
          session.expiresAt = new Date(
            Date.now() + this.config.sessionTimeoutMs,
          );
        }
        await this.storeSession(session);
      }
    });
  }

  /**
   * Enforce session limits for a user
   */
  private async enforceSessionLimits(
    userId: number,
    maxSessions?: number,
  ): Promise<void> {
    if (!this.isRedisAvailable()) {
      this.logger.warn(
        'Redis not available, skipping session limit enforcement',
      );
      return;
    }

    try {
      const limit = maxSessions || this.config.maxSessionsPerUser;
      const sessionIds = await this.getUserSessionIds(userId);

      if (sessionIds.length >= limit) {
        // Sort sessions by last activity (oldest first) to remove them
        const sessions: Array<{ id: string; lastActivity: Date }> = [];

        for (const sessionId of sessionIds) {
          const session = await this.getSession(sessionId);
          if (session) {
            sessions.push({
              id: sessionId,
              lastActivity: session.lastActivity,
            });
          }
        }

        // Sort by last activity (oldest first)
        sessions.sort(
          (a, b) => a.lastActivity.getTime() - b.lastActivity.getTime(),
        );

        // Remove oldest sessions to make room for new one
        const sessionsToRemove = sessions.length - limit + 1;
        for (let i = 0; i < sessionsToRemove && i < sessions.length; i++) {
          await this.destroySession(sessions[i].id);
          this.logger.log(
            `Removed old session ${sessions[i].id} for user ${userId} due to session limit`,
          );
        }
      }
    } catch (error) {
      this.logger.error(
        `Failed to enforce session limits for user ${userId}:`,
        error,
      );
      // Don't throw error, just log it - session creation should continue
    }
  }

  /**
   * Generate a simple device fingerprint from device info
   * Uses proper auth types for better type safety
   */
  private generateDeviceFingerprint(deviceInfo: DeviceInfo): string {
    // Ensure we have proper default values using auth types
    const deviceType: DeviceType = deviceInfo.deviceType || 'unknown';
    const browser = deviceInfo.browser || 'unknown';
    const os: string = deviceInfo.os || 'unknown';

    const fingerprintData = `${deviceInfo.userAgent}|${deviceInfo.ip}|${deviceType}|${browser}|${os}`;
    return crypto
      .createHash('sha256')
      .update(fingerprintData)
      .digest('hex')
      .substring(0, 16);
  }

  /**
   * Add session to user's session list with error handling
   */
  private async addToUserSessions(
    userId: number,
    sessionId: string,
  ): Promise<void> {
    await this.executeRedisOperation(async () => {
      const key = this.getUserSessionsKey(userId);
      await this.redisClient!.sAdd(key, sessionId);
      // await this.redisClient!.expire(
      //   key,
      //   Math.floor(this.config.sessionTimeoutMs / 1000),
      // );
    });
  }

  /**
   * Remove session from user's session list with error handling
   */
  private async removeFromUserSessions(
    userId: number,
    sessionId: string,
  ): Promise<void> {
    await this.executeRedisOperation(async () => {
      const key = this.getUserSessionsKey(userId);
      await this.redisClient!.sRem(key, sessionId);
    });
  }

  /**
   * Get user's session IDs with error handling
   */
  private async getUserSessionIds(userId: number): Promise<string[]> {
    const result = await this.executeRedisOperation(async () => {
      const key = this.getUserSessionsKey(userId);
      return this.redisClient!.sMembers(key);
    });
    return result || [];
  }

  /**
   * Get session key prefix - simple default without processing
   */
  private getSessionKeyPrefix(): string {
    return 'session:'; // Simple prefix, no automatic processing
  }

  private getSessionKey(sessionId: string): string {
    return `${this.redisConfig.keyPrefix}${sessionId}`;
  }

  private getUserSessionsKey(userId: number): string {
    return `${this.redisConfig.keyPrefix}user:${userId}:sessions`;
  }
}
