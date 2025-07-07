import { Injectable, Inject, Optional } from '@nestjs/common';
import { JwtService, JwtSignOptions } from '@nestjs/jwt';
import { Cache } from '@nestjs/cache-manager';
import * as jwt from 'jsonwebtoken';

/**
 * Enhanced AuthService with JWT and token revocation support
 * Provides comprehensive token management for both JWT and session-based authentication
 */
@Injectable()
export class AuthService {
  private readonly secretKey: string;

  constructor(
    @Optional() private readonly jwtService?: JwtService,
    @Optional() @Inject('CACHE_MANAGER') private readonly cacheManager?: Cache,
    @Optional()
    @Inject('AUTH_MODULE_OPTIONS')
    private readonly authOptions?: any,
  ) {
    this.secretKey =
      this.authOptions?.jwt?.secret || process.env.JWT_SECRET_KEY;
  }

  /**
   * Sign JWT token using NestJS JWT service or fallback to jsonwebtoken
   * @param payload - Token payload
   * @param options - JWT sign options
   * @returns Signed JWT token
   */
  sign(payload: any, options: JwtSignOptions = {}): string {
    try {
      // Use NestJS JWT service if available
      if (this.jwtService) {
        return this.jwtService.sign(payload, options);
      }

      // Fallback to direct jsonwebtoken usage
      return jwt.sign(payload, this.secretKey, options);
    } catch (error) {
      throw new Error(`Token signing failed: ${error.message}`);
    }
  }

  /**
   * Verify JWT token
   * @param token - JWT token to verify
   * @returns Decoded token payload
   */
  verify(token: string): any {
    try {
      // Use NestJS JWT service if available
      if (this.jwtService) {
        return this.jwtService.verify(token);
      }

      // Fallback to direct jsonwebtoken usage
      return jwt.verify(token, this.secretKey);
    } catch (error) {
      throw new Error(`Token verification failed: ${error.message}`);
    }
  }

  /**
   * Decode JWT token without verification
   * @param token - JWT token to decode
   * @returns Decoded token payload
   */
  decode(token: string): any {
    try {
      return jwt.decode(token);
    } catch (error) {
      throw new Error(`Token decoding failed: ${error.message}`);
    }
  }

  /**
   * Revoke a token by storing it in Redis with TTL
   * @param token - Token to revoke
   * @param ttl - Time to live in seconds (optional)
   * @returns Success status
   */
  async revokeToken(token: string, ttl?: number): Promise<boolean> {
    if (!this.cacheManager) {
      console.warn('Cache manager not available, token revocation skipped');
      return false;
    }

    try {
      // Get token expiration time for TTL
      const decoded = this.decode(token);
      const expirationTime = decoded?.exp
        ? decoded.exp * 1000
        : Date.now() + 24 * 60 * 60 * 1000;
      const calculatedTtl =
        ttl || Math.max(0, Math.floor((expirationTime - Date.now()) / 1000));

      // Store revoked token in Redis with TTL
      await this.cacheManager.set(
        `revoked_token:${token}`,
        true,
        calculatedTtl,
      );
      return true;
    } catch (error) {
      console.error('Failed to revoke token:', error);
      return false;
    }
  }

  /**
   * Check if token is revoked
   * @param token - Token to check
   * @returns True if token is revoked
   */
  async isTokenRevoked(token: string): Promise<boolean> {
    if (!this.cacheManager) {
      return false;
    }

    try {
      const isRevoked = await this.cacheManager.get(`revoked_token:${token}`);
      return !!isRevoked;
    } catch (error) {
      console.error('Failed to check token revocation:', error);
      return false;
    }
  }

  /**
   * Generate refresh token
   * @param payload - Token payload
   * @returns Refresh token
   */
  generateRefreshToken(payload: any): string {
    const refreshOptions: JwtSignOptions = {
      expiresIn: this.authOptions?.jwt?.refreshExpiresIn || '7d',
    };
    return this.sign(payload, refreshOptions);
  }

  /**
   * Generate access token
   * @param payload - Token payload
   * @returns Access token
   */
  generateAccessToken(payload: any): string {
    const accessOptions: JwtSignOptions = {
      expiresIn: this.authOptions?.jwt?.expiresIn || '1h',
    };
    return this.sign(payload, accessOptions);
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
    return {
      accessToken: this.generateAccessToken(payload),
      refreshToken: this.generateRefreshToken(payload),
    };
  }
}
