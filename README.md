# Universal NestJS Auth Package

[![npm version](https://badge.fury.io/js/universal-nestjs-auth-package.svg)](https://badge.fury.io/js/universal-nestjs-auth-package)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A comprehensive authentication package for NestJS applications providing **JWT** and **Session-based** authentication with a **unified interface**. Built with NestJS 11.x, Redis 5.x, and TypeScript 5.x. Uses strategy pattern for clean architecture and Redis-based session storage.

## 🚀 Key Features

- **Unified Interface**: Single `UnifiedAuthService` for both JWT and session authentication
- **Strategy Pattern**: Clean architecture with `IAuthStrategy` interface
- **Auto-Detection**: Automatically detects authentication method from requests
- **Multi-Device Sessions**: Track and manage sessions across devices with device fingerprinting
- **Token Revocation**: Secure JWT token invalidation with Redis
- **Device Fingerprinting**: Enhanced security through device tracking via user-agent analysis
- **Hybrid Mode**: Support both JWT and session authentication simultaneously
- **Configurable**: Extensive configuration options with environment variable support
- **TypeScript**: Full TypeScript support with comprehensive type definitions

## 📦 Installation

```bash
npm install universal-nestjs-auth-package
```

**Required Dependencies:**
- Redis server (4.x or 5.x)
- NestJS 11.x
- Node.js 16.x or higher

## 🎯 Quick Start

### 1. Module Setup

The package supports three authentication strategies:

#### Session-Based Authentication (Recommended)
```typescript
import { AuthModule } from 'universal-nestjs-auth-package';

@Module({
  imports: [
    AuthModule.forRoot({
      strategy: 'session',
      session: {
        secret: 'your-session-secret',
        name: 'myapp-session-id',
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        redis: {
          host: 'localhost',
          port: 6379,
          // password: 'your-redis-password', // if needed
          db: 0,
        },
        multiSession: {
          enabled: true,
          maxSessions: 5, // Allow up to 5 concurrent sessions
        },
      },
    }),
  ],
})
export class AppModule {}
```

#### JWT-Based Authentication
```typescript
import { AuthModule } from 'universal-nestjs-auth-package';

@Module({
  imports: [
    AuthModule.forRoot({
      strategy: 'jwt',
      jwt: {
        secret: 'your-jwt-secret',
        expiresIn: '1h',
        refreshExpiresIn: '7d',
      },
      cookies: {
        names: {
          accessToken: 'access-token',
          refreshToken: 'refresh-token',
        },
        options: {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'lax',
        },
      },
    }),
  ],
})
export class AppModule {}
```

#### Hybrid Mode (Both JWT and Session)
```typescript
import { AuthModule } from 'universal-nestjs-auth-package';

@Module({
  imports: [
    AuthModule.forRoot({
      strategy: 'hybrid',
      jwt: {
        secret: 'your-jwt-secret',
        expiresIn: '1h',
        refreshExpiresIn: '7d',
      },
      session: {
        secret: 'your-session-secret',
        name: 'myapp-session-id',
        maxAge: 24 * 60 * 60 * 1000,
        redis: {
          host: 'localhost',
          port: 6379,
        },
        multiSession: {
          enabled: true,
          maxSessions: 5,
        },
      },
      cookies: {
        names: {
          accessToken: 'access-token',
          refreshToken: 'refresh-token',
        },
      },
    }),
  ],
})
export class AppModule {}
```

### 2. Environment Variables

Configure the package using environment variables:

```bash
# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=your-redis-password
REDIS_SESSION_DB=0

# JWT Configuration
JWT_SECRET_KEY=your-jwt-secret
ACCESS_TOKEN_EXPIRATION=86400000  # 24 hours in milliseconds
REFRESH_TOKEN_EXPIRATION=604800000 # 7 days in milliseconds

# Session Configuration
SESSION_SECRET=your-session-secret
SESSION_NAME=myapp-session-id

# App Settings
NODE_ENV=production
```

### 3. Basic Usage

The `UnifiedAuthService` provides a **single interface** for all authentication methods:

```typescript
import { 
  UnifiedAuthService, 
  IUser, 
  UnifiedAuthInput,
  UnifiedAuthResult 
} from 'universal-nestjs-auth-package';

@Injectable()
export class AuthController {
  constructor(private readonly unifiedAuth: UnifiedAuthService) {}
  
  // Login - works with both JWT and session
  @Post('login')
  async login(
    @Body() loginDto: LoginDto, 
    @Req() request: Request
  ): Promise<UnifiedAuthResult> {
    // Your authentication logic here...
    const user = await this.validateUserCredentials(loginDto);
    
    const userData: IUser = {
      userId: user.id,
      email: user.email,
    };
    
    const authInput: UnifiedAuthInput = {
      userData,
      authMethod: 'auto', // or 'jwt' or 'session'
      options: {
        metadata: {
          loginTime: new Date(),
          userAgent: request.headers['user-agent'],
          ipAddress: request.ip,
        },
      },
    };
    
    return await this.unifiedAuth.login(authInput, request);
  }
  
  // Validate - automatically detects JWT or session
  @Get('me')
  async getCurrentUser(@Req() request: Request): Promise<IUser> {
    const result = await this.unifiedAuth.validateAuth(request);
    if (!result?.authenticated) {
      throw new UnauthorizedException();
    }
    return result.user;
  }
  
  // Logout - works with both JWT and session
  @Post('logout')
  async logout(@Req() request: Request) {
    return await this.unifiedAuth.logout(request);
  }
  
  // Get all user sessions
  @Get('sessions')
  async getUserSessions(@User() user: IUser) {
    return await this.unifiedAuth.getUserSessions(user.userId);
  }
  
  // Revoke all other sessions
  @Post('logout-others')
  async logoutOthers(@Req() request: Request, @User() user: IUser) {
    return await this.unifiedAuth.invalidateOtherSessions(
      user.userId, 
      request
    );
  }
}
```

## 🔐 Guards and Decorators

### Dynamic Authentication Decorator

The `@DynamicAuth()` decorator automatically detects authentication method:

```typescript
import { DynamicAuth, User, IUser } from 'universal-nestjs-auth-package';

@Controller('protected')
export class ProtectedController {
  
  // Auto-detect authentication method
  @Get('profile')
  @DynamicAuth()
  async getProfile(@User() user: IUser) {
    return { user, authMethod: 'auto-detected' };
  }
  
  // Force JWT authentication
  @Post('jwt-data')
  @DynamicAuth({ strategy: 'jwt' })
  async getJwtData(@User() user: IUser) {
    return { message: 'JWT authenticated', user };
  }
  
  // Force session authentication
  @Post('session-data')
  @DynamicAuth({ strategy: 'session' })
  async getSessionData(@User() user: IUser) {
    return { message: 'Session authenticated', user };
  }
  
  // Optional authentication (doesn't fail if no auth)
  @Get('public-data')
  @DynamicAuth({ optional: true })
  async getPublicData(@User() user?: IUser) {
    return { 
      message: 'Public endpoint',
      authenticated: !!user,
      user 
    };
  }
}
```

### Convenience Decorators

```typescript
import { 
  JwtAuth, 
  SessionAuth, 
  OptionalAuth,
  User,
  IUser 
} from 'universal-nestjs-auth-package';

@Controller('api')
export class ApiController {
  
  @Get('jwt-only')
  @JwtAuth() // Equivalent to @DynamicAuth({ strategy: 'jwt' })
  async jwtOnly(@User() user: IUser) {
    return { message: 'JWT only endpoint', user };
  }
  
  @Get('session-only')
  @SessionAuth() // Equivalent to @DynamicAuth({ strategy: 'session' })
  async sessionOnly(@User() user: IUser) {
    return { message: 'Session only endpoint', user };
  }
  
  @Get('optional')
  @OptionalAuth() // Equivalent to @DynamicAuth({ optional: true })
  async optional(@User() user?: IUser) {
    return { 
      message: 'Optional auth endpoint',
      authenticated: !!user,
      user 
    };
  }
}
```

### Manual Guards Usage

```typescript
import { 
  DynamicAuthGuard,
  JwtOnlyGuard,
  SessionOnlyGuard,
  OptionalDynamicAuthGuard 
} from 'universal-nestjs-auth-package';

@Controller('manual')
export class ManualController {
  
  @Get('dynamic')
  @UseGuards(DynamicAuthGuard)
  async dynamic(@User() user: IUser) {
    return { user };
  }
  
  @Get('jwt')
  @UseGuards(JwtOnlyGuard)
  async jwt(@User() user: IUser) {
    return { user };
  }
  
  @Get('session')
  @UseGuards(SessionOnlyGuard)
  async session(@User() user: IUser) {
    return { user };
  }
  
  @Get('optional')
  @UseGuards(OptionalDynamicAuthGuard)
  async optional(@User() user?: IUser) {
    return { user };
  }
}
```

## 🛠️ Advanced Configuration

### Complete Configuration Example

```typescript
import { AuthModule, AuthStrategy } from 'universal-nestjs-auth-package';

@Module({
  imports: [
    AuthModule.forRoot({
      strategy: 'hybrid' as AuthStrategy,
      
      // JWT Configuration
      jwt: {
        secret: process.env.JWT_SECRET_KEY || 'your-jwt-secret',
        expiresIn: '1h',
        refreshExpiresIn: '7d',
      },
      
      // Session Configuration
      session: {
        secret: process.env.SESSION_SECRET || 'your-session-secret',
        name: process.env.SESSION_NAME || 'myapp-session-id',
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        redis: {
          host: process.env.REDIS_HOST || 'localhost',
          port: parseInt(process.env.REDIS_PORT) || 6379,
          password: process.env.REDIS_PASSWORD,
          db: parseInt(process.env.REDIS_SESSION_DB) || 0,
        },
        multiSession: {
          enabled: true,
          maxSessions: 5,
        },
      },
      
      // Cookie Configuration (for JWT)
      cookies: {
        names: {
          accessToken: 'access-token',
          refreshToken: 'refresh-token',
        },
        options: {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'lax',
          domain: process.env.COOKIE_DOMAIN,
          path: '/',
        },
        rememberMe: {
          jwtMaxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
          jwtRegularMaxAge: 60 * 60 * 1000, // 1 hour
          refreshMaxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
        },
      },
    }),
  ],
})
export class AppModule {}
```

### Helper Service Usage

The `AuthHelperService` provides additional utilities:

```typescript
import { AuthHelperService, IUser } from 'universal-nestjs-auth-package';

@Injectable()
export class UserService {
  constructor(private readonly authHelper: AuthHelperService) {}
  
  // Complete user authentication with remember me
  async authenticateUser(
    userData: IUser,
    request: Request,
    rememberMe: boolean = false
  ) {
    return await this.authHelper.authenticateUser(
      userData,
      request,
      rememberMe
    );
  }
}
```

## 📋 Interfaces and Types

### Core Interfaces

```typescript
// User interface - extend as needed
interface IUser {
  userId: number;
  email: string;
  // Add your custom fields here
}

// Authentication result
interface UnifiedAuthResult {
  user: IUser;
  authenticated: boolean;
  authMethod: 'jwt' | 'session' | 'auto';
  timestamp: Date;
  token?: string; // JWT token
  refreshToken?: string; // JWT refresh token
  sessionId?: string;
  tokenInfo?: {
    expiresAt?: Date;
    issuedAt?: Date;
  };
}

// Authentication input
interface UnifiedAuthInput {
  userData: IUser;
  authMethod?: 'jwt' | 'session' | 'auto';
  options?: {
    expiresIn?: string | number;
    maxAge?: number;
    metadata?: Record<string, any>;
  };
}
```

### Available Types

```typescript
type AuthStrategy = 'jwt' | 'session' | 'hybrid';
type AuthMethod = 'jwt' | 'session' | 'auto';
type AuthStatus = 'authenticated' | 'unauthenticated' | 'expired' | 'invalid';
type SessionState = 'active' | 'expired' | 'revoked' | 'invalid';
type DeviceType = 'mobile' | 'tablet' | 'desktop' | 'unknown';
type CookieSameSite = 'strict' | 'lax' | 'none';
```

## 🧪 Testing Your Integration

### 1. Test Session Authentication
```bash
# Login
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password"}' \
  -c cookies.txt

# Access protected route
curl -X GET http://localhost:3000/protected/profile \
  -b cookies.txt

# Logout
curl -X POST http://localhost:3000/auth/logout \
  -b cookies.txt
```

### 2. Test JWT Authentication
```bash
# Login and extract token
TOKEN=$(curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password"}' \
  | jq -r '.token')

# Access protected route
curl -X GET http://localhost:3000/protected/profile \
  -H "Authorization: Bearer $TOKEN"
```

### 3. Test Multi-Device Sessions
```bash
# Check all sessions
curl -X GET http://localhost:3000/auth/sessions \
  -b cookies.txt

# Logout from all other devices
curl -X POST http://localhost:3000/auth/logout-others \
  -b cookies.txt
```

## 🔧 Requirements

- **Node.js**: 16.x or higher
- **NestJS**: 11.x
- **Redis**: 4.x or 5.x
- **TypeScript**: 5.x

## 🐛 Common Issues

### Redis Connection Issues
```bash
# Test Redis connection
redis-cli ping
# Should return: PONG

# Check Redis logs
redis-cli monitor
```

### Session Not Persisting
- Verify Redis is running and accessible
- Check session configuration (secret, name, redis connection)
- Ensure cookies are being sent by the client
- Verify Redis database number (db) is correct

### JWT Token Issues
- Verify JWT secret is consistent across restarts
- Check token expiration settings
- Ensure cookies are being set with correct options
- Verify Redis is available for token revocation

### TypeScript Errors
- Ensure you're using compatible NestJS and TypeScript versions
- Check that your `tsconfig.json` includes the package types
- Verify all required dependencies are installed

## 🛠️ Development

### Building the Package
```bash
npm run build
```

### Linting and Formatting
```bash
npm run lint
npm run format
```

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📞 Support

- **GitHub Issues**: [Create an issue](https://github.com/mohammedX6/universal-nestjs-auth-package/issues)
- **Documentation**: This README contains comprehensive examples
- **Community**: Check existing issues for common questions

---

**Built with ❤️ for the NestJS community**
