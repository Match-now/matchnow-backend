// ============================================
// 4. AppAuth Controller 수정 (src/auth/controllers/app-auth.controller.ts)
// ============================================

import {
  Controller,
  Post,
  Body,
  Get,
  UseGuards,
  Request,
  Patch,
  Delete,
  HttpCode,
  HttpStatus,
  Query,
  Ip,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiBody,
  ApiQuery,
} from '@nestjs/swagger';
import { AuthGuard } from '@nestjs/passport';
import { IsString, IsEmail, IsEnum, IsOptional, IsDateString, IsPhoneNumber, MinLength, MaxLength } from 'class-validator';

import { AppAuthService, SocialLoginDto, RefreshTokenDto } from '../services/app-auth.service';
import { SocialProvider, Gender } from '../../entities/app-user.entity';

class SocialLoginRequest implements SocialLoginDto {
  @IsEnum(SocialProvider, { message: '지원하는 소셜 로그인 제공자를 선택해주세요.' })
  provider: SocialProvider;

  @IsString()
  socialId: string;

  @IsOptional()
  @IsEmail({}, { message: '올바른 이메일 형식이 아닙니다.' })
  email?: string;

  @IsString()
  name: string;

  @IsOptional()
  @IsString()
  @MinLength(2, { message: '닉네임은 최소 2자 이상이어야 합니다.' })
  @MaxLength(20, { message: '닉네임은 최대 20자까지 입력 가능합니다.' })
  nickname?: string;

  @IsOptional()
  @IsString()
  profileImageUrl?: string;

  @IsOptional()
  @IsDateString({}, { message: '올바른 날짜 형식이 아닙니다. (YYYY-MM-DD)' })
  birthDate?: string;

  @IsOptional()
  @IsEnum(Gender, { message: '올바른 성별을 선택해주세요.' })
  gender?: Gender;

  @IsOptional()
  @IsPhoneNumber('KR', { message: '올바른 한국 전화번호 형식이 아닙니다.' })
  phoneNumber?: string;

  @IsOptional()
  @IsString()
  accessToken?: string;
}

class RefreshTokenRequest implements RefreshTokenDto {
  @IsString()
  @MinLength(10, { message: '올바른 Refresh Token을 입력해주세요.' })
  refreshToken: string;
}

class UpdateProfileRequest {
  @IsOptional()
  @IsString()
  name?: string;

  @IsOptional()
  @IsString()
  @MinLength(2, { message: '닉네임은 최소 2자 이상이어야 합니다.' })
  @MaxLength(20, { message: '닉네임은 최대 20자까지 입력 가능합니다.' })
  nickname?: string;

  @IsOptional()
  @IsString()
  profileImageUrl?: string;

  @IsOptional()
  @IsDateString({}, { message: '올바른 날짜 형식이 아닙니다. (YYYY-MM-DD)' })
  birthDate?: string;

  @IsOptional()
  @IsEnum(Gender, { message: '올바른 성별을 선택해주세요.' })
  gender?: Gender;

  @IsOptional()
  @IsPhoneNumber('KR', { message: '올바른 한국 전화번호 형식이 아닙니다.' })
  phoneNumber?: string;
}

@ApiTags('App User Authentication')
@Controller('/api/v1/app/auth')
export class AppAuthController {
  constructor(private readonly appAuthService: AppAuthService) {}

  @Post('social-login')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: '📱 SNS 소셜 로그인',
    description: `
**완전한 토큰 시스템:**
1. 📱 앱에서 SNS SDK로 로그인
2. 🖥️ 서버에서 Access Token(15분) + Refresh Token(7일) 발급
3. 📱 앱에서 두 토큰 모두 저장
4. 🔄 Access Token 만료 시 자동으로 Refresh Token으로 갱신

**응답 데이터:**
- accessToken: API 호출용 (15분 만료)
- refreshToken: 토큰 갱신용 (7일 만료, 갱신 시마다 새로 발급)
    `,
  })
  @ApiResponse({
    status: 200,
    description: 'SNS 로그인이 성공했습니다.',
    schema: {
      type: 'object',
      properties: {
        success: { type: 'boolean', example: true },
        data: {
          type: 'object',
          properties: {
            user: { type: 'object', description: '사용자 정보' },
            accessToken: { 
              type: 'string',
              description: 'JWT Access Token (15분 만료)',
              example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
            },
            refreshToken: { 
              type: 'string',
              description: 'JWT Refresh Token (7일 만료)',
              example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
            },
            isNewUser: { type: 'boolean', example: true },
          },
        },
        message: { type: 'string', example: '로그인이 성공했습니다.' },
      },
    },
  })
  @ApiBody({ 
    type: SocialLoginRequest,
    examples: {
      kakao_login: {
        summary: '🟡 카카오 로그인',
        value: {
          provider: 'kakao',
          socialId: '123456789',
          email: 'user@kakao.com',
          name: '홍길동',
          nickname: '길동이',
          profileImageUrl: 'https://k.kakaocdn.net/dn/profile.jpg'
        }
      }
    }
  })
  // socialLogin 메서드의 return 부분 수정:
  async socialLogin(@Body() socialLoginDto: SocialLoginRequest, @Ip() clientIp: string) {
    const result = await this.appAuthService.socialLogin(socialLoginDto, clientIp);
    
    const message = result.isNewUser ? '회원가입이 완료되었습니다.' : '로그인이 성공했습니다.';
    
    return {
      success: true,
      data: result,
      message, // 🔧 수정: 올바른 message 사용
    };
  }

  // 🆕 refresh API 추가 (controller에 누락된 부분)
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: '🔄 Access Token 갱신',
    description: `
  **자동 토큰 갱신 시스템:**
  1. 📱 API 호출 → 401 에러 (Access Token 만료)
  2. 📱 이 API로 Refresh Token을 body에 전송
  3. 🖥️ 서버에서 새로운 Access Token + Refresh Token 발급
  4. 📱 새 토큰들로 교체 후 원래 API 재호출

  **⚠️ 중요사항:**
  - Refresh Token은 **Authorization 헤더가 아닌 body**에 전송
  - 갱신할 때마다 **새로운 Refresh Token**도 함께 발급 (보안 강화)
  - 기존 Refresh Token은 즉시 무효화됨
    `,
  })
  @ApiResponse({
    status: 200,
    description: '토큰 갱신이 성공했습니다.',
    schema: {
      type: 'object',
      properties: {
        success: { type: 'boolean', example: true },
        data: {
          type: 'object',
          properties: {
            accessToken: { 
              type: 'string',
              description: '새로운 Access Token (15분)',
              example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
            },
            refreshToken: { 
              type: 'string',
              description: '새로운 Refresh Token (7일)',  
              example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
            },
          },
        },
        message: { type: 'string', example: '토큰이 성공적으로 갱신되었습니다.' },
      },
    },
  })
  @ApiResponse({
    status: 401,
    description: 'Refresh Token이 유효하지 않거나 만료되었습니다.',
  })
  @ApiBody({ 
    type: RefreshTokenRequest,
    description: 'Refresh Token을 body에 전송',
    examples: {
      refresh_request: {
        summary: '토큰 갱신 요청',
        value: {
          refreshToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
        }
      }
    }
  })
  async refreshToken(@Body() refreshTokenDto: RefreshTokenRequest, @Ip() clientIp: string) {
    const result = await this.appAuthService.refreshTokens(refreshTokenDto, clientIp);
    
    return {
      success: true,
      data: result,
      message: '토큰이 성공적으로 갱신되었습니다.',
    };
  }

  @Get('check-nickname')
  @ApiOperation({
    summary: '🔍 닉네임 중복 검증',
    description: '회원가입/프로필 수정 시 닉네임 사용 가능 여부를 확인합니다.',
  })
  @ApiQuery({
    name: 'nickname',
    required: true,
    description: '검증할 닉네임',
    example: '길동이',
  })
  async checkNickname(@Query('nickname') nickname: string) {
    if (!nickname || nickname.length < 2 || nickname.length > 20) {
      return {
        success: false,
        data: { isAvailable: false, nickname },
        message: '닉네임은 2자 이상 20자 이하로 입력해주세요.',
      };
    }

    const isAvailable = await this.appAuthService.checkNicknameAvailability(nickname);
    
    return {
      success: true,
      data: { isAvailable, nickname },
      message: isAvailable ? '사용 가능한 닉네임입니다.' : '이미 사용 중인 닉네임입니다.',
    };
  }

  @Post('logout')
  @UseGuards(AuthGuard('jwt'))
  @ApiBearerAuth()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: '🚪 로그아웃',
    description: '현재 사용자를 로그아웃시킵니다. (Refresh Token 무효화)',
  })
  async logout(@Request() req) {
    await this.appAuthService.logout(req.user.id);
    return {
      success: true,
      message: '로그아웃이 완료되었습니다.',
    };
  }

  @Get('profile')
  @UseGuards(AuthGuard('jwt'))
  @ApiBearerAuth()
  @ApiOperation({
    summary: '👤 사용자 프로필 조회',
    description: '현재 로그인된 사용자의 프로필 정보를 조회합니다.',
  })
  async getProfile(@Request() req) {
    return {
      success: true,
      data: req.user,
      message: '프로필 조회가 성공했습니다.',
    };
  }

  @Patch('profile')
  @UseGuards(AuthGuard('jwt'))
  @ApiBearerAuth()
  @ApiOperation({
    summary: '✏️ 사용자 프로필 수정',
    description: '현재 로그인된 사용자의 프로필 정보를 수정합니다.',
  })
  async updateProfile(@Body() updateProfileDto: UpdateProfileRequest, @Request() req) {
    const updatedUser = await this.appAuthService.updateProfile(req.user.id, {
      ...updateProfileDto,
      birthDate: updateProfileDto.birthDate ? new Date(updateProfileDto.birthDate) : undefined,
    });

    return {
      success: true,
      data: updatedUser,
      message: '프로필이 성공적으로 수정되었습니다.',
    };
  }

  @Delete('deactivate')
  @UseGuards(AuthGuard('jwt'))
  @ApiBearerAuth()
  @ApiOperation({
    summary: '🗑️ 계정 비활성화',
    description: '계정을 비활성화합니다. (로그인 불가, 복구 가능)',
  })
  async deactivateAccount(@Request() req) {
    await this.appAuthService.deactivateUser(req.user.id);
    return {
      success: true,
      message: '계정이 성공적으로 비활성화되었습니다.',
    };
  }

  @Delete('delete')
  @UseGuards(AuthGuard('jwt'))
  @ApiBearerAuth()
  @ApiOperation({
    summary: '💥 계정 완전 삭제',
    description: '계정을 완전히 삭제합니다. (복구 불가)',
  })
  async deleteAccount(@Request() req) {
    await this.appAuthService.deleteUser(req.user.id);
    return {
      success: true,
      message: '계정이 성공적으로 삭제되었습니다.',
    };
  }

  // 🆕 모든 기기에서 로그아웃 (보안상 필요 시)
  @Post('logout-all')
  @UseGuards(AuthGuard('jwt'))
  @ApiBearerAuth()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: '🚨 모든 기기에서 로그아웃',
    description: '모든 Refresh Token을 무효화하여 모든 기기에서 강제 로그아웃시킵니다.',
  })
  async logoutAll(@Request() req) {
    await this.appAuthService.revokeAllRefreshTokens(req.user.id);
    return {
      success: true,
      message: '모든 기기에서 로그아웃되었습니다.',
    };
  }
}