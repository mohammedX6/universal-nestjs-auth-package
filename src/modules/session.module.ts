import { DynamicModule, Module } from '@nestjs/common';
import { SessionService } from '../services/session/session.service';
import { SessionStrategyService } from '../services/session/session-strategy.service';
import { DeviceDetectionService } from '../services/device-detection.service';
import { SessionStrategy } from '../strategies/session.strategy';
import { SessionGuard, OptionalSessionGuard } from '../guards/session.guard';

export interface SessionModuleOptions {
  secret: string;
  name?: string;
  maxAge?: number; // Base session duration in milliseconds
  maxAgeRememberMe?: number; // Base session duration in milliseconds
  redis?: {
    host: string;
    port: number;
    password?: string;
    db?: number;
  };
  multiSession?: {
    enabled: boolean;
    maxSessions?: number;
    // Removed sessionTimeout - use maxAge instead for consistency
  };
}

/**
 * Session Module for managing session-based authentication
 * Provides services and guards for session management
 */
@Module({})
export class SessionModule {
  /**
   * Configure the session module with dynamic options
   * @param options - Session configuration options
   * @returns DynamicModule with configured providers
   */
  static forRoot(options: SessionModuleOptions): DynamicModule {
    return {
      module: SessionModule,
      providers: [
        {
          provide: 'SESSION_MODULE_OPTIONS',
          useValue: options,
        },
        SessionService,
        SessionStrategyService,
        DeviceDetectionService,
        SessionStrategy,
        SessionGuard,
        OptionalSessionGuard,
      ],
      exports: [
        SessionService,
        SessionStrategyService,
        DeviceDetectionService,
        SessionStrategy,
        SessionGuard,
        OptionalSessionGuard,
        'SESSION_MODULE_OPTIONS',
      ],
      global: true,
    };
  }
}
