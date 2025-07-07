import {
  Injectable,
  UnauthorizedException,
  Inject,
  Optional,
} from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-custom';
import { Request } from 'express';
import { DeviceDetectionService } from '../services/device-detection.service';
import { SessionStrategyService } from '../services/session/session-strategy.service';
import { AuthModuleOptions } from '../modules/auth.module';
import { extractSessionId } from '../utils/index';

/**
 * Session-based authentication strategy
 * Replaces JWT strategy with session validation
 * Now properly receives configuration from forRoot method
 */
@Injectable()
export class SessionStrategy extends PassportStrategy(Strategy, 'session') {
  constructor(
    private readonly sessionStrategyService: SessionStrategyService,
    private readonly deviceDetectionService: DeviceDetectionService,
    @Optional()
    @Inject('AUTH_MODULE_OPTIONS')
    private readonly authOptions?: AuthModuleOptions,
  ) {
    super();
  }

  /**
   * Validate session from request
   * @param req - Express request object
   * @returns User data if session is valid
   */
  async validate(req: Request): Promise<any> {
    try {
      // Get session ID from cookie or header
      const sessionId = this.extractSessionId(req);

      if (!sessionId) {
        throw new UnauthorizedException('No session found');
      }

      // Validate session
      const validation = await this.sessionStrategyService.validateAuth(req);

      if (!validation?.authenticated) {
        throw new UnauthorizedException('Invalid session');
      }

      // Add session info to request
      req.sessionId = validation.sessionId;

      // Return user data for further processing
      return validation.user;
    } catch (error) {
      throw new UnauthorizedException('Session validation failed');
    }
  }

  /**
   * Extract session ID from request using centralized utility
   * @param req - Express request object
   * @returns Session ID or null
   */
  private extractSessionId(req: Request): string | null {
    // Use the centralized utility function with configured session name
    const sessionName =
      this.authOptions?.session?.name ||
      process.env.SESSION_NAME ||
      'sessionId';
    return extractSessionId(req, sessionName);
  }
}
