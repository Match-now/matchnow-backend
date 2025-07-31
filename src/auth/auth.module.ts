// src/auth/auth.module.ts (간소화된 실용적 버전)
import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { ConfigModule, ConfigService } from '@nestjs/config';

import { AdminUser } from '../entities/admin-user.entity';
import { AppUser } from '../entities/app-user.entity';
import { AdminAuthService } from './services/admin-auth.service';
import { AppAuthService } from './services/app-auth.service';
import { AdminAuthController } from './controllers/admin-auth.controller';
import { AppAuthController } from './controllers/app-auth.controller';
import { JwtStrategy } from './strategies/jwt.strategy';

// 🎯 필요한 것만 import: JWT 전략만 사용
// ❌ 제거된 것들: KakaoStrategy, GoogleStrategy, AppleStrategy
// 이유: 앱에서 SNS 로그인을 처리하므로 서버에 SNS 전략 불필요

@Module({
  imports: [
    TypeOrmModule.forFeature([AdminUser, AppUser]),
    PassportModule.register({ 
      defaultStrategy: 'jwt',
      session: false, // 세션 비활성화 (JWT 토큰만 사용)
    }),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_SECRET'),
        signOptions: {
          expiresIn: configService.get<string>('JWT_EXPIRES_IN', '7d'),
        },
      }),
    }),
  ],
  providers: [
    // 인증 서비스들
    AdminAuthService, 
    AppAuthService, 
    
    // JWT 전략만 필요 (SNS 전략들은 불필요)
    JwtStrategy,
  ],
  controllers: [
    AdminAuthController, 
    AppAuthController,
  ],
  exports: [AdminAuthService, AppAuthService, JwtModule],
})
export class AuthModule {}

/*
🚀 간소화 이유:

1. **클라이언트 주도 SNS 로그인**
   - 앱에서 카카오/구글/애플 SDK로 직접 로그인
   - 서버는 결과만 받아서 처리
   - 더 안전하고 UX가 좋음

2. **제거된 패키지들**
   - passport-kakao
   - passport-google-oauth20  
   - passport-apple
   - 관련 @types 패키지들

3. **필요한 것만 유지**
   - JWT 인증 (서버 인증용)
   - 기본 Passport 모듈
   - TypeORM (사용자 관리용)

4. **실제 모바일 앱 개발 패턴**
   - React Native: expo-auth-session, react-native-kakao-login
   - Flutter: kakao_flutter_sdk, google_sign_in
   - Native: 각 플랫폼 공식 SDK

💡 결론: 서버는 가볍게, 앱은 풍부하게!
*/