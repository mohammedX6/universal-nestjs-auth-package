import { Injectable, CanActivate, ExecutionContext, Inject, UnauthorizedException } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Request } from 'express';
import { AuthModuleOptions } from '../modules/auth.module';

/**
 * Enhanced Dynamic Authentication Guard
 * Automatically detects and uses the appropriate authentication strategy
 * based on the request and module configuration with improved logic
 */
@Injectable()
export class DynamicAuthGuard implements CanActivate {
  constructor(
    @Inject('AUTH_MODULE_OPTIONS')
    private readonly authOptions: AuthModuleOptions,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();
    
    // Determine which authentication method to use based on request
    const authMethod = this.detectAuthMethod(request);
    
    let guard: CanActivate;
    
    try {
      switch (authMethod) {
        case 'jwt':
          if (this.authOptions.strategy === 'session') {
            throw new UnauthorizedException('JWT authentication not supported in session-only mode');
          }
          guard = new (AuthGuard('jwt'))();
          break;
          
        case 'session':
          if (this.authOptions.strategy === 'jwt') {
            throw new UnauthorizedException('Session authentication not supported in JWT-only mode');
          }
          guard = new (AuthGuard('session'))();
          break;
          
        default:
          // Auto-detect mode - use the most appropriate strategy
          guard = this.createAutoDetectGuard(request);
          break;
      }
      
      return await guard.canActivate(context) as boolean;
    } catch (error) {
      // In hybrid mode, try the fallback strategy if the primary fails
      if (this.authOptions.strategy === 'hybrid' && authMethod === 'auto') {
        return await this.tryFallbackAuth(context, request);
      }
      throw error;
    }
  }

  /**
   * Create guard for auto-detection mode
   * @param request - HTTP request object
   * @returns Appropriate guard instance
   */
  private createAutoDetectGuard(request: Request): CanActivate {
    if (this.authOptions.strategy === 'jwt') {
      return new (AuthGuard('jwt'))();
    } else if (this.authOptions.strategy === 'session') {
      return new (AuthGuard('session'))();
    } else {
      // Hybrid mode - prefer session if available, fallback to JWT
      const hasSession = this.hasSessionData(request);
      const hasJwt = this.hasJwtData(request);
      
      if (hasSession && hasJwt) {
        // If both are present, prefer session
        return new (AuthGuard('session'))();
      } else if (hasSession) {
        return new (AuthGuard('session'))();
      } else if (hasJwt) {
        return new (AuthGuard('jwt'))();
      } else {
        // No auth data found - default to JWT for better error messages
        return new (AuthGuard('jwt'))();
      }
    }
  }

  /**
   * Try fallback authentication in hybrid mode
   * @param context - Execution context
   * @param request - HTTP request
   * @returns Authentication result
   */
  private async tryFallbackAuth(context: ExecutionContext, request: Request): Promise<boolean> {
    try {
      // Try the opposite strategy
      const hasSession = this.hasSessionData(request);
      const fallbackGuard = hasSession 
        ? new (AuthGuard('jwt'))() 
        : new (AuthGuard('session'))();
      
      return await fallbackGuard.canActivate(context) as boolean;
    } catch (fallbackError) {
      // Both strategies failed
      throw new UnauthorizedException('Authentication failed with all available strategies');
    }
  }

  /**
   * Detect authentication method based on request
   * @param request - HTTP request object
   * @returns Authentication method to use
   */
  private detectAuthMethod(request: Request): 'jwt' | 'session' | 'auto' {
    // Check for explicit JWT token in Authorization header
    const authHeader = request.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      return 'jwt';
    }
    
    // Check for JWT token in cookies using configured cookie name
    const accessTokenCookieName = this.authOptions?.cookies?.names?.accessToken || 'access-token';
    const jwtCookie = request.cookies?.[accessTokenCookieName];
    if (jwtCookie) {
      return 'jwt';
    }
    
    // Check for session data
    if (this.hasSessionData(request)) {
      return 'session';
    }
    
    return 'auto';
  }

  /**
   * Check if request has JWT data
   * @param request - HTTP request object
   * @returns True if JWT data exists
   */
  private hasJwtData(request: Request): boolean {
    // Check Authorization header
    const authHeader = request.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      return true;
    }
    
    // Check JWT cookie using configured cookie name
    const accessTokenCookieName = this.authOptions?.cookies?.names?.accessToken || 'access-token';
    const jwtCookie = request.cookies?.[accessTokenCookieName];
    if (jwtCookie) {
      return true;
    }
    
    return false;
  }

  /**
   * Check if request has session data
   * @param request - HTTP request object
   * @returns True if session data exists
   */
  private hasSessionData(request: Request): boolean {
    // Check for session cookie
    // Use session name exactly as configured, from environment, or default
    const sessionName = this.authOptions.session?.name || process.env.SESSION_NAME || 'sessionId';
    const sessionCookie = request.cookies?.[sessionName];
    if (sessionCookie) {
      return true;
    }
    
    // Check for session ID in headers
    const sessionHeader = request.headers['x-session-id'];
    if (sessionHeader) {
      return true;
    }
    
    // Check for session data in request (if session middleware is active)
    if (request.session && (request.session as any).userId) {
      return true;
    }
    
    return false;
  }
}

/**
 * Optional Dynamic Authentication Guard
 * Same as DynamicAuthGuard but doesn't throw error if no authentication is found
 */
@Injectable()
export class OptionalDynamicAuthGuard extends DynamicAuthGuard {
  async canActivate(context: ExecutionContext): Promise<boolean> {
    try {
      return await super.canActivate(context);
    } catch (error) {
      // If authentication fails, allow the request to continue
      // but don't populate user data
      return true;
    }
  }
}

/**
 * Strategy-specific guards for explicit strategy selection
 */

@Injectable()
export class JwtOnlyGuard extends AuthGuard('jwt') {
  constructor(
    @Inject('AUTH_MODULE_OPTIONS')
    private readonly authOptions: AuthModuleOptions,
  ) {
    super();
    
    if (this.authOptions.strategy === 'session') {
      throw new Error('JWT guard cannot be used in session-only mode');
    }
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    try {
      return await super.canActivate(context) as boolean;
    } catch (error) {
      throw new UnauthorizedException('JWT authentication failed');
    }
  }
}

@Injectable()
export class SessionOnlyGuard extends AuthGuard('session') {
  constructor(
    @Inject('AUTH_MODULE_OPTIONS')
    private readonly authOptions: AuthModuleOptions,
  ) {
    super();
    
    if (this.authOptions.strategy === 'jwt') {
      throw new Error('Session guard cannot be used in JWT-only mode');
    }
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    try {
      return await super.canActivate(context) as boolean;
    } catch (error) {
      throw new UnauthorizedException('Session authentication failed');
    }
  }
} 