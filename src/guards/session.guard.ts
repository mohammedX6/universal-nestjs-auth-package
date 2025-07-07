import {
  Injectable,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

// Extend Express Request interface to include user
declare global {
  namespace Express {
    interface Request {
      user?: any;
      userSession?: any;
      sessionId?: string;
    }
  }
}

/**
 * Session-based authentication guard
 * Replaces JWT guard with session validation
 */
@Injectable()
export class SessionGuard extends AuthGuard('session') {
  canActivate(context: ExecutionContext) {
    return super.canActivate(context);
  }

  handleRequest(err: any, user: any, info: any, context: ExecutionContext) {
    if (err || !user) {
      throw err || new UnauthorizedException('Invalid session');
    }

    // Add user and session info to request
    const request = context.switchToHttp().getRequest();
    request.user = user;

    return user;
  }
}

/**
 * Optional session guard - doesn't throw error if no session
 * Useful for endpoints that work with or without authentication
 */
@Injectable()
export class OptionalSessionGuard extends SessionGuard {
  handleRequest(err: any, user: any, info: any, context: ExecutionContext) {
    // Don't throw error if no user - just return null
    if (err || !user) {
      return null;
    }

    const request = context.switchToHttp().getRequest();
    request.user = user;

    return user;
  }
}
