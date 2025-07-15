import {
  Injectable,
  UnauthorizedException,
  Inject,
  Optional,
} from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { AuthService } from '../services/jwt/auth.service';
import { Request } from 'express';
import { Cache } from '@nestjs/cache-manager';

/**
 * Enhanced JWT Strategy with Redis-based token revocation
 * This strategy validates tokens and checks if they are revoked using Redis cache
 * Can be used across all microservices without requiring user repositories
 *
 * Token revocation is handled by storing revoked tokens directly in Redis with TTL
 */
@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(
    private readonly authService: AuthService,
    @Optional() @Inject('CACHE_MANAGER') private readonly cacheManager?: Cache,
    @Optional()
    @Inject('AUTH_MODULE_OPTIONS')
    private readonly authOptions?: any,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        // Primary: Extract from cookies for browser clients using configured cookie name
        (request: Request) => {
          let token = null;
          if (request?.cookies) {
            const accessTokenCookieName =
              authOptions?.cookies?.names?.accessToken || 'access-token';
            token = request.cookies[accessTokenCookieName];
          }
          return token;
        },
        // Secondary: Fallback to Bearer header extraction for API clients
        ExtractJwt.fromAuthHeaderAsBearerToken(),
      ]),
      secretOrKey:
        authOptions?.jwt?.secret ||
        process.env.JWT_SECRET_KEY ||
        'sawtak-jwt-secret',
      // Pass the request to validate method so we can access the raw token
      passReqToCallback: true,
    });
  }

  /**
   * Validates the JWT payload and checks for token revocation using Redis
   * @param request - The HTTP request object
   * @param payload - The decoded JWT payload
   * @returns The user data from the payload if valid
   * @throws UnauthorizedException if token is revoked
   */
  async validate(request: Request, payload: any): Promise<any> {
    try {
      // Extract the raw token from request using configured cookie name
      let token = null;
      if (request?.cookies) {
        const accessTokenCookieName =
          this.authOptions?.cookies?.names?.accessToken || 'access-token';
        token = request.cookies[accessTokenCookieName];
      }

      if (!token) {
        // Extract from Authorization header
        const authHeader = request.headers.authorization;
        if (authHeader && authHeader.startsWith('Bearer ')) {
          token = authHeader.substring(7);
        }
      }

      if (!token) {
        throw new UnauthorizedException('No token provided');
      }

      // Check if token is revoked using Redis - store token directly
      if (this.cacheManager) {
        try {
          const isRevoked = await this.cacheManager.get(
            `revoked_token:${token}`,
          );

          if (isRevoked) {
            throw new UnauthorizedException('Token has been revoked');
          }
        } catch (error) {
          // If it's our revocation error, re-throw it
          if (error instanceof UnauthorizedException) {
            throw error;
          }
          // Log cache errors but don't fail validation
          console.error('Error checking token revocation in Redis:', error);
        }
      }

      // Token is valid and not revoked
      return payload;
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error;
      }
      throw new UnauthorizedException('Token validation failed');
    }
  }

  /**
   * Check if cache manager is available
   * @returns boolean indicating if cache manager is available
   */
  isCacheAvailable(): boolean {
    return !!this.cacheManager;
  }
}
