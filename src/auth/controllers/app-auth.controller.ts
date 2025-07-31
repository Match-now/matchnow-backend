// src/auth/controllers/app-auth.controller.ts (간소화된 실용적 버전)
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

import { AppAuthService, SocialLoginDto } from '../services/app-auth.service';
import { SocialProvider, Gender } from '../../entities/app-user.entity';

class SocialLoginRequest implements SocialLoginDto {
  @IsEnum(SocialProvider, { message: '지원하는 소셜 로그인 제공자를 선택해주세요.' })
  provider: SocialProvider;

  @IsString()
  socialId: string; // 앱에서 받은 SNS 고유 ID

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

  // 🔐 선택적 토큰 검증용 (보안 강화 시 사용)
  @IsOptional()
  @IsString()
  accessToken?: string; // SNS에서 받은 액세스 토큰 (검증용)
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

  // 🎯 핵심 API: 클라이언트에서 SNS 로그인 완료 후 서버에 결과 전달
  @Post('social-login')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: '📱 SNS 소셜 로그인 결과 처리',
    description: `
**실제 사용 플로우:**
1. 📱 앱에서 SNS SDK로 로그인 (카카오/구글/애플)
2. 📱 앱에서 받은 사용자 정보를 이 API로 전송
3. 🖥️ 서버에서 사용자 생성/업데이트 후 JWT 토큰 발급

**필수 정보:** provider, socialId, name
**선택 정보:** email, nickname, profileImageUrl 등
    `,
  })
  @ApiResponse({
    status: 200,
    description: 'SNS 로그인 처리가 성공했습니다.',
    schema: {
      type: 'object',
      properties: {
        success: { type: 'boolean', example: true },
        data: {
          type: 'object',
          properties: {
            user: { 
              type: 'object',
              description: '사용자 정보 (비밀번호 제외)'
            },
            accessToken: { 
              type: 'string',
              description: 'JWT 토큰 (7일 만료)',
              example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
            },
            isNewUser: { 
              type: 'boolean',
              description: '신규 가입 여부',
              example: true
            },
          },
        },
        message: { type: 'string', example: '회원가입이 완료되었습니다.' },
      },
    },
  })
  @ApiResponse({
    status: 400,
    description: '잘못된 요청 데이터입니다.',
  })
  @ApiResponse({
    status: 409,
    description: '닉네임이 이미 사용 중입니다.',
  })
  @ApiBody({ 
    type: SocialLoginRequest,
    description: '앱에서 SNS 로그인 후 받은 사용자 정보',
    examples: {
      kakao_new_user: {
        summary: '🆕 카카오 신규 사용자',
        description: '카카오 로그인 후 첫 가입하는 사용자',
        value: {
          provider: 'kakao',
          socialId: '123456789',
          email: 'user@kakao.com',
          name: '홍길동',
          nickname: '길동이',
          profileImageUrl: 'https://k.kakaocdn.net/dn/profile.jpg'
        }
      },
      google_existing_user: {
        summary: '🔄 구글 기존 사용자',
        description: '이미 가입한 구글 사용자의 재로그인',
        value: {
          provider: 'google',
          socialId: 'google_987654321',
          email: 'user@gmail.com',
          name: '김철수',
          profileImageUrl: 'https://lh3.googleusercontent.com/profile.jpg'
        }
      },
      apple_minimal: {
        summary: '🍎 애플 최소 정보',
        description: '애플은 이름/이메일을 제공하지 않을 수 있음',
        value: {
          provider: 'apple',
          socialId: 'apple_555666777',
          name: '사용자',
          nickname: 'user123'
        }
      }
    }
  })
  async socialLogin(@Body() socialLoginDto: SocialLoginRequest, @Request() req) {
    const clientIp = req.ip || req.connection.remoteAddress;
    const result = await this.appAuthService.socialLogin(socialLoginDto, clientIp);
    
    const message = result.isNewUser ? '회원가입이 완료되었습니다.' : '로그인이 성공했습니다.';
    
    return {
      success: true,
      data: result,
      message,
    };
  }

  // 🔍 닉네임 중복 검증 API
  @Get('check-nickname')
  @ApiOperation({
    summary: '🔍 닉네임 중복 검증',
    description: '회원가입/프로필 수정 시 닉네임 사용 가능 여부를 확인합니다.',
  })
  @ApiResponse({
    status: 200,
    description: '닉네임 검증이 완료되었습니다.',
    schema: {
      type: 'object',
      properties: {
        success: { type: 'boolean', example: true },
        data: {
          type: 'object',
          properties: {
            isAvailable: { type: 'boolean', example: true },
            nickname: { type: 'string', example: '길동이' },
          },
        },
        message: { type: 'string', example: '사용 가능한 닉네임입니다.' },
      },
    },
  })
  @ApiQuery({
    name: 'nickname',
    required: true,
    description: '검증할 닉네임 (2-20자, 한글/영문/숫자/일부 특수문자)',
    example: '길동이',
  })
  async checkNickname(@Query('nickname') nickname: string) {
    if (!nickname || nickname.length < 2 || nickname.length > 20) {
      return {
        success: false,
        data: {
          isAvailable: false,
          nickname,
        },
        message: '닉네임은 2자 이상 20자 이하로 입력해주세요.',
      };
    }

    const isAvailable = await this.appAuthService.checkNicknameAvailability(nickname);
    
    return {
      success: true,
      data: {
        isAvailable,
        nickname,
      },
      message: isAvailable ? '사용 가능한 닉네임입니다.' : '이미 사용 중인 닉네임입니다.',
    };
  }

  // 🚪 로그아웃 API
  @Post('logout')
  @UseGuards(AuthGuard('jwt'))
  @ApiBearerAuth()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: '🚪 로그아웃',
    description: '현재 사용자를 로그아웃시킵니다. (토큰 무효화)',
  })
  @ApiResponse({
    status: 200,
    description: '로그아웃이 성공했습니다.',
  })
  async logout(@Request() req) {
    await this.appAuthService.logout(req.user.id);
    return {
      success: true,
      message: '로그아웃이 완료되었습니다.',
    };
  }

  // 👤 프로필 조회
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

  // ✏️ 프로필 수정
  @Patch('profile')
  @UseGuards(AuthGuard('jwt'))
  @ApiBearerAuth()
  @ApiOperation({
    summary: '✏️ 사용자 프로필 수정',
    description: '현재 로그인된 사용자의 프로필 정보를 수정합니다.',
  })
  @ApiResponse({
    status: 409,
    description: '이미 사용 중인 닉네임입니다.',
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

  // 🗑️ 계정 관리
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
}