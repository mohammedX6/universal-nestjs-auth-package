import { IUser } from './user.interface';
import { DeviceType, SessionState, AuthStatus } from '../types/auth.types';

/**
 * Device information for session tracking
 * Uses proper auth types for better type safety
 */
export interface DeviceInfo {
  userAgent: string;
  ip: string;
  deviceType: DeviceType;
  browser?: string;
  os?: string;
  fingerprint: string;
  isTrusted?: boolean;
}

/**
 * User session data structure
 * Supports multi-device sessions with device fingerprinting
 * Uses proper auth types for better type safety
 */
export interface UserSession {
  sessionId: string;
  userId: number;
  deviceInfo: DeviceInfo;
  userData: IUser;
  createdAt: Date;
  lastActivity: Date;
  expiresAt: Date;
  isActive: boolean;
  state?: SessionState;
  metadata?: Record<string, any>;
}

/**
 * Session invalidation policy for password changes
 */
export enum PasswordChangeSessionPolicy {
  INVALIDATE_ALL = 'invalidate_all', // Maximum security
  INVALIDATE_OTHERS = 'invalidate_others', // Balanced security
  KEEP_ALL = 'keep_all', // Maximum convenience
  USER_CHOICE = 'user_choice', // Let user decide
}

/**
 * Session validation result
 * Uses proper auth types for better type safety
 */
export interface SessionValidationResult {
  isValid: boolean;
  status?: AuthStatus;
  session?: UserSession;
  user?: IUser;
  error?: string;
}

/**
 * Session creation options
 */
export interface SessionCreateOptions {
  maxSessions?: number;
  sessionTimeout?: number;
  extendOnActivity?: boolean;
  requireDeviceValidation?: boolean;
  trackLocation?: boolean;
  metadata?: Record<string, any>;
}
