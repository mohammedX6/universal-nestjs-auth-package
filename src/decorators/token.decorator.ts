import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { Request } from 'express';
import { extractJwtTokenFromRequest } from '../utils/index';

/**
 * Token extraction decorator for shared auth package
 * This decorator extracts JWT tokens from HTTP requests, supporting multiple extraction methods:
 * 1. Cookie-based authentication (configurable cookie name) - Primary method for browser clients
 * 2. Bearer token authentication (Authorization header) - For API clients and mobile apps
 *
 * Usage examples:
 * @Token() token: string - Gets the raw JWT token using default cookie name
 * @Token('my-token') token: string - Gets the raw JWT token using custom cookie name
 *
 * The decorator follows the same extraction order as JwtStrategy for consistency:
 * 1. Check cookies for configured cookie name (default: 'access-token')
 * 2. Fallback to Authorization header with 'Bearer ' prefix
 *
 * Note: If you need to use a custom cookie name, you can pass it as the data parameter.
 * For full dynamic configuration support, use the auth guards and strategies instead.
 */
export const Token = createParamDecorator(
  (data: string | undefined, ctx: ExecutionContext): string | null => {
    const request: Request = ctx.switchToHttp().getRequest();

    // Use the data parameter as cookie name if provided, otherwise default to 'access-token'
    const cookieName = data || 'access-token';

    // Use the utility function for consistent token extraction
    return extractJwtTokenFromRequest(request, cookieName);
  },
);
