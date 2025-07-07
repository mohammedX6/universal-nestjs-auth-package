import { Injectable, Inject, Optional } from '@nestjs/common';
import { Request, Response } from 'express';
import { UnifiedAuthService } from './unified-auth.service';
import { UnifiedAuthInput, UnifiedAuthResult, IUser } from '../interfaces/user.interface';
import { AuthModuleOptions } from '../modules/auth.module';


@Injectable()
export class AuthHelperService {
  // Default configuration values - used when not provided in config
  private readonly defaultCookieNames = {
    accessToken: 'access-token',
    refreshToken: 'refresh-token',
    sessionId: 'session-id',
  };

  private readonly defaultCookieOptions = {
    httpOnly: true,
    secure: true,
    sameSite: 'none' as const,
    path: '/',
  };

  private readonly defaultRememberMeConfig = {
    jwtMaxAge: 30 * 24 * 60 * 60 * 1000,        // 30 days
    refreshMaxAge: 30 * 24 * 60 * 60 * 1000,    // 30 days
    jwtRegularMaxAge: 60 * 60 * 1000,            // 1 hour
    // Session timing now uses session.maxAge as base - no defaults here
    sessionMaxAge: undefined,                    // Use session.maxAge or fallback to 24 hours
    sessionRegularMaxAge: undefined,             // Use session.maxAge or fallback to 24 hours
  };

  constructor(
    private readonly unifiedAuthService: UnifiedAuthService,
    @Optional() @Inject('AUTH_MODULE_OPTIONS') private readonly authOptions?: AuthModuleOptions,
  ) {}

  /**
   * Get cookie names from configuration with fallback to defaults
   * @returns Cookie names configuration
   */
  private getCookieNames() {
    return {
      accessToken: this.authOptions?.cookies?.names?.accessToken || this.defaultCookieNames.accessToken,
      refreshToken: this.authOptions?.cookies?.names?.refreshToken || this.defaultCookieNames.refreshToken,
      // Use session name from session config only
      sessionId: this.authOptions?.session?.name || process.env.SESSION_NAME || 'sessionId',
    };
  }

  /**
   * Get cookie options from configuration with fallback to defaults
   * @returns Cookie options configuration
   */
  private getCookieOptions() {
    return {
      httpOnly: this.authOptions?.cookies?.options?.httpOnly ?? this.defaultCookieOptions.httpOnly,
      secure: this.authOptions?.cookies?.options?.secure ?? this.defaultCookieOptions.secure,
      sameSite: this.authOptions?.cookies?.options?.sameSite || this.defaultCookieOptions.sameSite,
      path: this.authOptions?.cookies?.options?.path || this.defaultCookieOptions.path,
      ...(this.authOptions?.cookies?.options?.domain && { domain: this.authOptions.cookies.options.domain }),
    };
  }

  /**
   * Get remember me configuration from options with fallback to defaults
   * Session timing uses session.maxAge as base, only override if specifically configured
   * @returns Remember me configuration
   */
  private getRememberMeConfig() {
    return {
      jwtMaxAge: this.authOptions?.cookies?.rememberMe?.jwtMaxAge || this.defaultRememberMeConfig.jwtMaxAge,
      refreshMaxAge: this.authOptions?.cookies?.rememberMe?.refreshMaxAge || this.defaultRememberMeConfig.refreshMaxAge,
      jwtRegularMaxAge: this.authOptions?.cookies?.rememberMe?.jwtRegularMaxAge || this.defaultRememberMeConfig.jwtRegularMaxAge,
      // Session timing is now handled in session configuration only
    };
  }

  /**
   * Complete user authentication and create session/tokens
   * Handles both JWT and Session authentication with rememberMe support
   * Can be used for any authentication flow (OTP, password, social login, etc.)
   * @param userData - User data from authentication verification
   * @param request - HTTP request object
   * @param rememberMe - Whether to extend session/token expiration
   * @returns Authentication result with tokens/session info
   */
  async authenticateUser(
    userData: IUser,
    request: Request,
    rememberMe: boolean = false
  ): Promise<UnifiedAuthResult> {
    try {
      // Extract request metadata
      const userAgent = request?.headers?.['user-agent'] || 'unknown';
      const clientIp = request?.ip || request?.connection?.remoteAddress || 'unknown';
      const requestTime = new Date();

      // Calculate expiration times based on rememberMe flag and configuration
      const jwtExpiration = rememberMe 
        ? this.authOptions?.jwt?.refreshExpiresIn || '30d'
        : this.authOptions?.jwt?.expiresIn || '1h';
      
      // Use session.maxAge directly (session timing is configured in session section only)
      const sessionMaxAge = this.authOptions?.session?.maxAge || 24 * 60 * 60 * 1000; // 24 hours default

      // Create unified auth input
      const authInput: UnifiedAuthInput = {
        userData,
        authMethod: 'auto', // Let unified service decide based on configuration
        options: {
          expiresIn: jwtExpiration,
          maxAge: sessionMaxAge,
          metadata: {
            loginTime: requestTime,
            userAgent: userAgent,
            ipAddress: clientIp,
            rememberMe: rememberMe,
          },
        },
      };

      // Use unified auth service to create authentication
      const authResult = await this.unifiedAuthService.login(authInput, request);

      return authResult;
    } catch (error) {
      throw new Error(`User authentication failed: ${error.message}`);
    }
  }

  /**
   * Set authentication cookies based on auth result and rememberMe preference
   * Uses dynamic configuration for cookie names, options, and expiration times
   * @param response - HTTP response object
   * @param authResult - Authentication result from unified service
   * @param rememberMe - Whether to extend cookie expiration
   */
  setAuthCookies(response: Response, authResult: UnifiedAuthResult, rememberMe: boolean = false): void {
    // Get configuration values
    const cookieNames = this.getCookieNames();
    const cookieOptions = this.getCookieOptions();
    const rememberMeConfig = this.getRememberMeConfig();

    // Calculate cookie expiration times based on rememberMe flag and configuration
    // Session timing is configured in session section only
    const sessionMaxAge = rememberMe
      ? this.authOptions?.session?.maxAgeRememberMe || 7 * 24 * 60 * 60 * 1000 // 7 days default
      : this.authOptions?.session?.maxAge || 24 * 60 * 60 * 1000; // 24 hours default

    const jwtMaxAge = rememberMe 
      ? rememberMeConfig.jwtMaxAge
      : rememberMeConfig.jwtRegularMaxAge;

    const refreshMaxAge = rememberMe 
      ? rememberMeConfig.refreshMaxAge
      : rememberMeConfig.refreshMaxAge; // Refresh tokens typically always have longer expiration

    // Handle JWT authentication cookies
    if (authResult.authMethod === 'jwt' && authResult.token) {
      // Set access token cookie
      response.cookie(cookieNames.accessToken, authResult.token, {
        ...cookieOptions,
        maxAge: jwtMaxAge,
      });

      // Set refresh token cookie if available (use refresh token expiration)
      response.cookie(cookieNames.refreshToken, authResult.token, {
        ...cookieOptions,
        maxAge: refreshMaxAge,
      });
    }

    // Handle Session authentication - session ID with configured expiration for rememberMe
    if (authResult.authMethod === 'session' && authResult.sessionId) {
      response.cookie(cookieNames.sessionId, authResult.sessionId, {
        ...cookieOptions,
        maxAge: sessionMaxAge,
      });
    }
  }

  /**
   * Clear all authentication cookies using configured cookie names
   * @param response - HTTP response object
   */
  clearAuthCookies(response: Response): void {
    // Get configured cookie names
    const cookieNames = this.getCookieNames();
    
    // Clear all authentication cookies using configured names
    response.clearCookie(cookieNames.accessToken);
    response.clearCookie(cookieNames.refreshToken);
    response.clearCookie(cookieNames.sessionId);
  }

  /**
   * Terminate user session and clear authentication
   * Handles both JWT token revocation and session termination
   * @param request - HTTP request object
   * @param response - HTTP response object
   * @param userId - Optional user ID for logging
   * @returns Logout result
   */
  async terminateAuth(
    request: Request, 
    response: Response, 
    userId?: number
  ): Promise<{ success: boolean; methods: string[]; message: string }> {
    try {
      // Use unified auth service for logout
      const unifiedLogoutResult = await this.unifiedAuthService.logout(request);

      // Clear all authentication cookies
      this.clearAuthCookies(response);

      const message = userId
        ? `User ${userId} logged out successfully using ${unifiedLogoutResult.method.join(', ')}`
        : `User logged out successfully using ${unifiedLogoutResult.method.join(', ')}`;

      return {
        success: unifiedLogoutResult.success,
        methods: unifiedLogoutResult.method,
        message,
      };
    } catch (error) {
      // Clear cookies even if logout fails for security
      this.clearAuthCookies(response);

      return {
        success: false,
        methods: [],
        message: 'Logout completed with errors',
      };
    }
  }


  /**
   * Refresh authentication tokens/session
   * @param request - HTTP request object
   * @param response - HTTP response object
   * @param rememberMe - Whether to maintain extended expiration
   * @returns Refreshed authentication result
   */
  async refreshAuthTokens(
    request: Request, 
    response: Response, 
    rememberMe: boolean = false
  ): Promise<UnifiedAuthResult | null> {
    try {
      const refreshResult = await this.unifiedAuthService.refresh(request);
      
      if (refreshResult) {
        // Update cookies with new tokens/session info
        this.setAuthCookies(response, refreshResult, rememberMe);
      }

      return refreshResult;
    } catch (error) {
      return null;
    }
  }

  /**
   * Get all active user sessions/tokens
   * @param userId - User ID
   * @param strategyType - Optional strategy type filter
   * @returns Array of session information
   */
  async getActiveSessions(userId: number, strategyType?: 'jwt' | 'session') {
    return await this.unifiedAuthService.getUserSessions(userId, strategyType);
  }

  /**
   * Revoke all user sessions/tokens
   * @param userId - User ID
   * @param strategyType - Optional strategy type filter
   * @returns Number of revoked sessions
   */
  async revokeAllSessions(userId: number, strategyType?: 'jwt' | 'session') {
    return await this.unifiedAuthService.invalidateAllUserSessions(userId, strategyType);
  }

  /**
   * Update user data across all active sessions
   * Useful for propagating profile changes, role updates, etc.
   * @param userId - User ID whose sessions to update
   * @param updateData - Partial user data to update in sessions
   * @returns Number of sessions successfully updated
   */
  async updateUserSessionsData(
    userId: number,
    updateData: Partial<IUser>
  ): Promise<number> {
    return await this.unifiedAuthService.updateAllUserSessionsData(userId, updateData);
  }

  /**
   * Update specific fields across all active user sessions
   * More granular control over what gets updated
   * @param userId - User ID whose sessions to update
   * @param fieldUpdates - Object with field names and new values
   * @returns Number of sessions successfully updated
   */
  async updateUserSessionsFields(
    userId: number,
    fieldUpdates: Record<string, any>
  ): Promise<number> {
    return await this.unifiedAuthService.updateUserSessionsFields(userId, fieldUpdates);
  }

  /**
   * Check if authentication service is available
   * @returns True if authentication is available
   */
  isServiceAvailable(): boolean {
    return this.unifiedAuthService.isAvailable();
  }

  /**
   * Get current authentication helper configuration
   * Useful for debugging and verifying configuration
   * @returns Current configuration values being used
   */
  getServiceConfig() {
    return {
      cookieNames: this.getCookieNames(),
      cookieOptions: this.getCookieOptions(),
      rememberMeConfig: this.getRememberMeConfig(),
      authStrategy: this.authOptions?.strategy || 'auto',
      isServiceAvailable: this.isServiceAvailable(),
    };
  }
} 