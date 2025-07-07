# Universal NestJS Auth Package

[![npm version](https://badge.fury.io/js/universal-nestjs-auth-package.svg)](https://badge.fury.io/js/universal-nestjs-auth-package)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A comprehensive authentication package for NestJS applications providing **JWT** and **Session-based** authentication with a **unified interface**. Built with the latest NestJS 11.x, Redis 5.x, and TypeScript 5.x. Uses strategy pattern for clean architecture and Redis-only session storage.

## 🚀 Key Features

- **Unified Interface**: Single service for both JWT and session authentication
- **Strategy Pattern**: Clean architecture with IAuthStrategy interface
- **Auto-Detection**: Automatically detects authentication method from requests
- **Multi-Device Sessions**: Track and manage sessions across devices
- **Token Revocation**: Secure JWT token invalidation with Redis
- **Device Fingerprinting**: Enhanced security through device tracking
- **Configurable Naming**: Customize session and cookie names for your application
- **Environment Variables**: Support for both configuration and environment-based setup
- **TypeScript**: Full type safety and IntelliSense support
- **Modern Dependencies**: Updated to latest NestJS 11.x, Redis 5.x, and TypeScript 5.x
- **ESLint Ready**: Clean, linted codebase with modern ESLint v9 configuration

## 📦 Installation

```bash
npm install universal-nestjs-auth-package
```

## 🎯 Quick Start

### 1. Module Setup

Choose your authentication strategy:

#### JWT Only
```typescript
import { AuthModule } from 'universal-nestjs-auth-package';

@Module({
  imports: [
    AuthModule.forRoot({
      strategy: 'jwt',
      jwt: {
        secret: 'your-jwt-secret',
        expiresIn: '1h',
      },
      redis: {
        host: 'localhost',
        port: 6379,
      },
    }),
  ],
})
export class AppModule {}
```

#### Session Only
```typescript
import { AuthModule } from 'universal-nestjs-auth-package';

@Module({
  imports: [
    AuthModule.forRoot({
      strategy: 'session',
      session: {
        secret: 'your-session-secret',
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
      },
      redis: {
        host: 'localhost',
        port: 6379,
      },
    }),
  ],
})
export class AppModule {}
```

#### Hybrid (Both JWT and Session)
```typescript
import { AuthModule } from 'universal-nestjs-auth-package';

@Module({
  imports: [
    AuthModule.forRoot({
      strategy: 'hybrid',
      jwt: {
        secret: 'your-jwt-secret',
        expiresIn: '1h',
      },
      session: {
        secret: 'your-session-secret',
        maxAge: 24 * 60 * 60 * 1000,
      },
      redis: {
        host: 'localhost',
        port: 6379,
        password: 'your-redis-password', // if needed
      },
    }),
  ],
})
export class AppModule {}
```

### 2. Environment Variables Configuration

You can also configure the package using environment variables:

```bash
# App naming (affects session and cookie names)
APP_NAME=myapp
SESSION_PREFIX=myapp

# JWT Configuration
JWT_SECRET_KEY=your-jwt-secret
ACCESS_TOKEN_EXPIRATION=86400000  # 24 hours in milliseconds
REFRESH_TOKEN_EXPIRATION=172800000 # 48 hours in milliseconds

# Session Configuration
SESSION_SECRET=your-session-secret
SESSION_TTL=86400 # 24 hours in seconds

# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=your-redis-password
REDIS_SESSION_DB=1

# Session Management
MAX_SESSIONS_PER_USER=5
SESSION_TIMEOUT=86400
SESSION_CLEANUP_INTERVAL=3600
```

### 3. Basic Usage

The `UnifiedAuthService` provides a **single interface** for all authentication methods:

```typescript
import { UnifiedAuthService, IUser, UnifiedAuthInput } from 'universal-nestjs-auth-package';

@Injectable()
export class AuthController {
  constructor(private unifiedAuth: UnifiedAuthService) {}
  
  // Login - works with both JWT and session
  @Post('login')
  async login(@Body() loginDto: LoginDto, @Req() request: Request) {
    // Your authentication logic here...
    const userData: IUser = {
      userId: user.id,
      email: user.email,
      userName: user.userName,
      // Add any domain-specific fields
      organizationId: user.organizationId, // e.g., companyId, projectId, etc.
      userTypeId: user.userTypeId,
      permissions: user.permissions,
    };
    
    const authInput: UnifiedAuthInput = {
      userData,
      authMethod: 'auto', // or 'jwt' or 'session'
    };
    
    const result = await this.unifiedAuth.login(authInput, request);
    return result;
  }
  
  // Validate - automatically detects JWT or session
  @Get('me')
  async getCurrentUser(@Req() request: Request) {
    const result = await this.unifiedAuth.validateAuth(request);
    if (!result?.authenticated) {
      throw new UnauthorizedException();
    }
    return result.user;
  }
  
  // Logout - works with both JWT and session
  @Post('logout')
  async logout(@Req() request: Request) {
    const result = await this.unifiedAuth.logout(request);
    return result;
  }
}
```

## 🔐 Guards and Decorators

### Dynamic Authentication Guard
```typescript
import { DynamicAuth, User } from 'universal-nestjs-auth-package';

@Controller('protected')
@DynamicAuth() // Automatically detects JWT or session
export class ProtectedController {
  
  @Get('profile')
  async getProfile(@User() user: IUser) {
    return user;
  }
  
  @Post('data')
  @DynamicAuth({ strategy: 'jwt' }) // Force JWT only
  async getData(@User() user: IUser) {
    return { message: 'JWT authenticated', user };
  }
}
```

### Strategy-Specific Guards
```typescript
import { 
  JwtOnlyGuard, 
  SessionOnlyGuard, 
  OptionalDynamicAuthGuard 
} from 'universal-nestjs-auth-package';

@Controller('api')
export class ApiController {
  
  @Get('jwt-only')
  @UseGuards(JwtOnlyGuard)
  async jwtOnly(@User() user: IUser) {
    return { message: 'JWT only endpoint', user };
  }
  
  @Get('session-only')
  @UseGuards(SessionOnlyGuard)
  async sessionOnly(@User() user: IUser) {
    return { message: 'Session only endpoint', user };
  }
  
  @Get('optional-auth')
  @UseGuards(OptionalDynamicAuthGuard)
  async optionalAuth(@User() user?: IUser) {
    return { 
      message: 'Optional auth endpoint', 
      authenticated: !!user,
      user 
    };
  }
}
```

## 🛠️ Advanced Configuration

### Custom Session and Cookie Names
```typescript
AuthModule.forRoot({
  strategy: 'hybrid',
  jwt: { secret: 'jwt-secret' },
  session: { 
    secret: 'session-secret',
    name: 'myapp.session.id', // Custom session name - configured here only
    maxAge: 24 * 60 * 60 * 1000 // Session max age - configured here only
  },
  cookies: {
    names: {
      accessToken: 'myapp-access-token',  // JWT cookie names
      refreshToken: 'myapp-refresh-token',
    },
    options: {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      domain: '.myapp.com',
    },
  },
})
```

### Multi-Device Session Management
```typescript
AuthModule.forRoot({
  strategy: 'session',
  session: {
    secret: 'session-secret',
    multiSession: {
      enabled: true,
      maxSessions: 10, // Allow up to 10 concurrent sessions
    },
  },
})
```



## 🔧 Requirements

- **Node.js**: 16.x or higher
- **NestJS**: 11.x or higher
- **Redis**: 4.x or 5.x
- **TypeScript**: 5.x

## 🛠️ Development

### Building the Package
```bash
npm run build
```

### Linting
```bash
npm run lint
```

### Code Formatting
```bash
npm run format
```

## 🔍 Troubleshooting

### Common Issues

**Redis Connection Issues**
```bash
# Ensure Redis is running
redis-cli ping
# Should return: PONG
```

**TypeScript Errors**
- Ensure your `tsconfig.json` includes the package types
- Check that you're using compatible NestJS and TypeScript versions

**Session Not Working**
- Verify Redis connection and configuration
- Check that session cookies are being set correctly
- Ensure your Redis database is accessible

**JWT Token Issues**
- Verify JWT secret is set correctly
- Check token expiration settings
- Ensure Redis is available for token revocation

## 🤝 Support

For issues and questions:
- Check the [GitHub Issues](https://github.com/mohammedX6/universal-nestjs-auth-package/issues)
- Review the examples in this README
- Ensure Redis is running and accessible
- Verify your configuration matches the examples

## 📄 License

MIT License - see LICENSE file for details.

---
