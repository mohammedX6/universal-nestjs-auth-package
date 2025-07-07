import { randomBytes } from 'crypto';
import { Request } from 'express';

/**
 * Utility functions for authentication and session management
 */

/**
 * Extract session ID from request
 * @param request - Express request object
 * @param sessionName - Session cookie name (optional, uses environment or default)
 * @returns Session ID or null
 */
export function extractSessionId(
  request: Request,
  sessionName: string = process.env.SESSION_NAME || 'sessionId',
): string | null {
  // Use session name exactly as provided
  // Check cookies first
  if (request.cookies && request.cookies[sessionName]) {
    return request.cookies[sessionName];
  }

  // Check Authorization header with Session prefix
  const authHeader = request.headers.authorization;
  if (authHeader && authHeader.startsWith('Session ')) {
    return authHeader.substring(8);
  }

  // Check custom header
  const sessionHeader = request.headers['x-session-id'];
  if (sessionHeader) {
    return sessionHeader as string;
  }

  return null;
}

/**
 * Check if request has authentication data
 * @param request - Express request object
 * @returns Object indicating what auth data is present
 */
export function detectAuthData(request: Request): {
  hasJwt: boolean;
  hasSession: boolean;
  authType: 'jwt' | 'session' | 'both' | 'none';
} {
  const hasJwt = !!extractJwtTokenFromRequest(request, 'access-token');
  const hasSession = !!extractSessionId(request);

  let authType: 'jwt' | 'session' | 'both' | 'none';
  if (hasJwt && hasSession) {
    authType = 'both';
  } else if (hasJwt) {
    authType = 'jwt';
  } else if (hasSession) {
    authType = 'session';
  } else {
    authType = 'none';
  }

  return { hasJwt, hasSession, authType };
}

/**
 * Get client IP address from request
 * @param request - Express request object
 * @returns Client IP address
 */
export function getClientIp(request: Request): string {
  // Check for forwarded IP (proxy/load balancer)
  const forwarded = request.headers['x-forwarded-for'];
  if (forwarded) {
    return (forwarded as string).split(',')[0].trim();
  }

  // Check for real IP
  const realIp = request.headers['x-real-ip'];
  if (realIp) {
    return realIp as string;
  }

  // Fallback to connection remote address
  return (
    request.connection.remoteAddress ||
    request.socket.remoteAddress ||
    '127.0.0.1'
  );
}

/**
 * Extract JWT token from request using dynamic cookie names
 * This utility function can be used by decorators and other components
 * @param request - HTTP request object
 * @param accessTokenCookieName - Optional cookie name override
 * @returns JWT token or null
 */
export function extractJwtTokenFromRequest(
  request: any,
  accessTokenCookieName: string = 'access-token',
): string | null {
  let token: string | null = null;

  // Primary: Extract from cookies for browser clients using configured name
  if (request.cookies && request.cookies[accessTokenCookieName]) {
    token = request.cookies[accessTokenCookieName];
  } else {
    // Secondary: Fallback to Bearer header extraction for API clients
    const authHeader = request.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.substring(7); // Remove 'Bearer ' prefix
    }
  }

  return token;
}

/**
 * Generate a cryptographically secure session ID
 * Uses Node.js crypto.randomBytes for maximum security
 * 
 * @param length - Length in bytes for the session ID (default: 32 bytes = 256 bits)
 * @returns A URL-safe, cryptographically secure session ID
 */
export function generateSecureSessionId(length: number = 32): string {
  // Generate cryptographically secure random bytes
  // Default: 32 bytes = 256 bits of entropy (extremely secure)
  const randomBuffer = randomBytes(length);
  
  // Convert to URL-safe base64 string
  const sessionId = randomBuffer
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
  
  return sessionId;
}



