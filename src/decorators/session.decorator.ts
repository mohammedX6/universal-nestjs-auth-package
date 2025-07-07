import { createParamDecorator, ExecutionContext } from '@nestjs/common';

/**
 * Extract session ID from request
 * Usage: @GetSessionId() sessionId: string
 */
export const GetSessionId = createParamDecorator(
  (data: unknown, ctx: ExecutionContext): string => {
    const request = ctx.switchToHttp().getRequest();
    return request.sessionId;
  },
);

/**
 * Extract full session object from request
 * Usage: @GetSession() session: UserSession
 */
export const GetSession = createParamDecorator(
  (data: unknown, ctx: ExecutionContext): any => {
    const request = ctx.switchToHttp().getRequest();
    return request.userSession;
  },
);

/**
 * Extract user ID from session
 * Usage: @GetUserId() userId: number
 */
export const GetUserId = createParamDecorator(
  (data: unknown, ctx: ExecutionContext): number => {
    const request = ctx.switchToHttp().getRequest();
    return request.user?.userId || request.userSession?.userId;
  },
);

/**
 * Extract device info from session
 * Usage: @GetDeviceInfo() deviceInfo: DeviceInfo
 */
export const GetDeviceInfo = createParamDecorator(
  (data: unknown, ctx: ExecutionContext): any => {
    const request = ctx.switchToHttp().getRequest();
    return request.userSession?.deviceInfo;
  },
);

/**
 * Extract specific user data field from session
 * Usage: @GetUserData('email') email: string
 */
export const GetUserData = createParamDecorator(
  (field: string, ctx: ExecutionContext): any => {
    const request = ctx.switchToHttp().getRequest();
    const userData = request.user || request.userSession?.userData;
    return field ? userData?.[field] : userData;
  },
);
