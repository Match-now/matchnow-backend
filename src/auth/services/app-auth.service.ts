// ============================================
// 🔧 수정된 AppAuth Service (src/auth/services/app-auth.service.ts)
// 타입 에러 해결 버전
// ============================================

import { Injectable, UnauthorizedException, BadRequestException, ConflictException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

import { AppUser, SocialProvider, AppUserStatus, Gender } from '../../entities/app-user.entity';

export interface SocialLoginDto {
  provider: SocialProvider;
  socialId: string;
  email?: string;
  name: string;
  nickname?: string;
  profileImageUrl?: string;
  birthDate?: string;
  gender?: Gender;
  phoneNumber?: string;
  accessToken?: string;
  refreshToken?: string;
}

export interface AppLoginResponse {
  user: AppUser;
  accessToken: string;
  refreshToken: string; // 🆕 refreshToken도 응답에 포함
  isNewUser: boolean;
}

export interface RefreshTokenDto {
  refreshToken: string;
}

export interface RefreshTokenResponse {
  accessToken: string;
  refreshToken: string; // 🆕 새로운 refreshToken
}

@Injectable()
export class AppAuthService {
  constructor(
    @InjectRepository(AppUser)
    private appUserRepository: Repository<AppUser>,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  async socialLogin(socialLoginDto: SocialLoginDto, clientIp?: string): Promise<AppLoginResponse> {
    const {
      provider,
      socialId,
      email,
      name,
      nickname,
      profileImageUrl,
      birthDate,
      gender,
      phoneNumber,
    } = socialLoginDto;

    // 고유 식별자 생성 (provider + socialId)
    const uniqueSocialId = `${socialId}@${provider}`;

    // 기존 사용자 확인
    let user = await this.appUserRepository.findOne({
      where: { socialId: uniqueSocialId, provider },
    });

    let isNewUser = false;

    if (!user) {
      // 🆕 닉네임 중복 검증 (회원가입 시)
      if (nickname) {
        const isNicknameAvailable = await this.checkNicknameAvailability(nickname);
        if (!isNicknameAvailable) {
          throw new ConflictException('이미 사용 중인 닉네임입니다.');
        }
      }

      // 신규 사용자 생성
      user = this.appUserRepository.create({
        socialId: uniqueSocialId,
        provider,
        email,
        name,
        nickname: nickname || name,
        profileImageUrl,
        birthDate: birthDate ? new Date(birthDate) : undefined,
        gender,
        phoneNumber,
        status: AppUserStatus.ACTIVE,
      });

      user = await this.appUserRepository.save(user);
      isNewUser = true;
    } else {
      // 기존 사용자 정보 업데이트
      await this.appUserRepository.update(user.id, {
        email: email || user.email,
        name: name || user.name,
        nickname: user.nickname || nickname || name,
        profileImageUrl: profileImageUrl || user.profileImageUrl,
        birthDate: birthDate ? new Date(birthDate) : user.birthDate,
        gender: gender || user.gender,
        phoneNumber: phoneNumber || user.phoneNumber,
        lastLoginAt: new Date(),
        lastLoginIp: clientIp,
      });

      // 업데이트된 사용자 정보 다시 조회
      user = await this.appUserRepository.findOne({
        where: { id: user.id },
      });

      if (!user) {
        throw new Error('사용자 정보를 다시 조회할 수 없습니다.');
      }
    }

    // 계정 상태 확인
    if (user.status !== AppUserStatus.ACTIVE) {
      throw new UnauthorizedException('비활성화된 계정입니다.');
    }

    // 🆕 Access Token과 Refresh Token 모두 생성
    const { accessToken, refreshToken } = await this.generateTokenPair(user);

    // 🆕 Refresh Token을 DB에 저장
    await this.saveRefreshToken(user.id, refreshToken);

    return {
      user,
      accessToken,
      refreshToken,
      isNewUser,
    };
  }

  // 🆕 토큰 갱신 메서드
  async refreshTokens(refreshTokenDto: RefreshTokenDto, clientIp?: string): Promise<RefreshTokenResponse> {
    const { refreshToken } = refreshTokenDto;

    try {
      // 1. Refresh Token 검증
      const payload = this.jwtService.verify(refreshToken, {
        secret: this.configService.get<string>('JWT_SECRET'),
      });

      // 2. Refresh Token 타입 확인
      if (payload.tokenType !== 'refresh') {
        throw new UnauthorizedException('Invalid token type');
      }

      // 3. 사용자 조회 및 저장된 Refresh Token과 비교
      const user = await this.appUserRepository.findOne({
        where: { id: payload.sub },
      });

      if (!user) {
        throw new UnauthorizedException('사용자를 찾을 수 없습니다.');
      }

      if (user.status !== AppUserStatus.ACTIVE) {
        throw new UnauthorizedException('비활성화된 계정입니다.');
      }

      // 4. 저장된 Refresh Token과 일치하는지 확인
      if (user.refreshToken !== refreshToken) {
        throw new UnauthorizedException('Invalid refresh token');
      }

      // 5. Refresh Token 만료 시간 확인
      if (user.refreshTokenExpiresAt && user.refreshTokenExpiresAt < new Date()) {
        throw new UnauthorizedException('Refresh token expired');
      }

      // 6. 새로운 토큰 쌍 생성
      const newTokens = await this.generateTokenPair(user);

      // 7. 새로운 Refresh Token을 DB에 저장
      await this.saveRefreshToken(user.id, newTokens.refreshToken);

      // 8. 마지막 로그인 정보 업데이트
      await this.appUserRepository.update(user.id, {
        lastLoginAt: new Date(),
        lastLoginIp: clientIp,
      });

      return {
        accessToken: newTokens.accessToken,
        refreshToken: newTokens.refreshToken,
      };
    } catch (error) {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }
  }

  // 🆕 토큰 쌍 생성 메서드
  private async generateTokenPair(user: AppUser): Promise<{ accessToken: string; refreshToken: string }> {
    const payload = {
      sub: user.id,
      email: user.email,
      type: 'app' as const,
      provider: user.provider,
      nickname: user.nickname,
    };

    // Access Token (짧은 만료 시간)
    const accessToken = this.jwtService.sign({
      ...payload,
      tokenType: 'access',
    }, {
      expiresIn: this.configService.get<string>('JWT_ACCESS_EXPIRES_IN', '15m'), // 🔧 환경변수 사용
    });

    // Refresh Token (긴 만료 시간)
    const refreshToken = this.jwtService.sign({
      ...payload,
      tokenType: 'refresh',
    }, {
      expiresIn: this.configService.get<string>('JWT_REFRESH_EXPIRES_IN', '7d'), // 🔧 환경변수 사용
    });

    return { accessToken, refreshToken };
  }

  // 🆕 Refresh Token DB 저장 메서드
  private async saveRefreshToken(userId: number, refreshToken: string): Promise<void> {
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7); // 7일 후 만료

    await this.appUserRepository.update(userId, {
      refreshToken,
      refreshTokenExpiresAt: expiresAt,
      refreshTokenIssuedAt: new Date(),
    });
  }

  // 🔧 수정: Refresh Token 무효화 (로그아웃 시) - 타입 에러 해결
  async revokeRefreshToken(userId: number): Promise<void> {
    // 방법 1: undefined 사용 (추천)
    await this.appUserRepository.update(userId, {
      refreshToken: undefined,
      refreshTokenExpiresAt: undefined,
      refreshTokenIssuedAt: undefined,
    });

    // 방법 2: 또는 직접 쿼리 사용
    // await this.appUserRepository
    //   .createQueryBuilder()
    //   .update(AppUser)
    //   .set({
    //     refreshToken: () => 'NULL',
    //     refreshTokenExpiresAt: () => 'NULL',
    //     refreshTokenIssuedAt: () => 'NULL',
    //   })
    //   .where('id = :id', { id: userId })
    //   .execute();
  }

  // 🆕 모든 Refresh Token 무효화 (보안상 필요 시)
  async revokeAllRefreshTokens(userId: number): Promise<void> {
    await this.revokeRefreshToken(userId);
  }

  // 🆕 닉네임 중복 검증
  async checkNicknameAvailability(nickname: string): Promise<boolean> {
    if (!nickname || nickname.trim().length === 0) {
      return false;
    }

    if (nickname.length < 2 || nickname.length > 20) {
      return false;
    }

    const nicknameRegex = /^[가-힣a-zA-Z0-9_.-]+$/;
    if (!nicknameRegex.test(nickname)) {
      return false;
    }

    const forbiddenWords = ['admin', '관리자', 'null', 'undefined', 'test'];
    if (forbiddenWords.some(word => nickname.toLowerCase().includes(word.toLowerCase()))) {
      return false;
    }

    const existingUser = await this.appUserRepository.findOne({
      where: { nickname },
    });

    return !existingUser;
  }

  // 🔧 수정: 로그아웃 (토큰 무효화) - 타입 에러 해결
  async logout(userId: number): Promise<void> {
    await this.revokeRefreshToken(userId);
  }

  async validateUser(id: number): Promise<AppUser | null> {
    return this.appUserRepository.findOne({
      where: { id, status: AppUserStatus.ACTIVE },
    });
  }

  async updateProfile(userId: number, updateData: Partial<AppUser>): Promise<AppUser> {
    const user = await this.appUserRepository.findOne({
      where: { id: userId },
    });

    if (!user) {
      throw new BadRequestException('사용자를 찾을 수 없습니다.');
    }

    if (updateData.nickname && updateData.nickname !== user.nickname) {
      const isNicknameAvailable = await this.checkNicknameAvailability(updateData.nickname);
      if (!isNicknameAvailable) {
        throw new ConflictException('이미 사용 중인 닉네임입니다.');
      }
    }

    const allowedFields = [
      'name',
      'nickname',
      'profileImageUrl',
      'birthDate',
      'gender',
      'phoneNumber',
    ];

    const filteredUpdateData = Object.keys(updateData)
      .filter(key => allowedFields.includes(key))
      .reduce((obj, key) => {
        obj[key] = updateData[key];
        return obj;
      }, {});

    await this.appUserRepository.update(userId, filteredUpdateData);

    const updatedUser = await this.appUserRepository.findOne({
      where: { id: userId },
    });

    if (!updatedUser) {
      throw new BadRequestException('업데이트된 사용자 정보를 조회할 수 없습니다.');
    }

    return updatedUser;
  }

  // 🔧 수정: 계정 비활성화 - 타입 에러 해결
  async deactivateUser(userId: number): Promise<void> {
    // 방법 1: undefined 사용 (추천)
    await this.appUserRepository.update(userId, {
      status: AppUserStatus.INACTIVE,
      refreshToken: undefined,
      refreshTokenExpiresAt: undefined,
      refreshTokenIssuedAt: undefined,
    });

    // 방법 2: 또는 직접 쿼리 사용
    // await this.appUserRepository
    //   .createQueryBuilder()
    //   .update(AppUser)
    //   .set({
    //     status: AppUserStatus.INACTIVE,
    //     refreshToken: () => 'NULL',
    //     refreshTokenExpiresAt: () => 'NULL',
    //     refreshTokenIssuedAt: () => 'NULL',
    //   })
    //   .where('id = :id', { id: userId })
    //   .execute();
  }

  async deleteUser(userId: number): Promise<void> {
    // Soft delete 전에 토큰도 무효화
    await this.revokeRefreshToken(userId);
    await this.appUserRepository.softDelete(userId);
  }

  // 사용자 통계 조회
  async getUserStats(): Promise<any> {
    const [totalUsers, activeUsers, inactiveUsers, newUsersToday] = await Promise.all([
      this.appUserRepository.count(),
      this.appUserRepository.count({
        where: { status: AppUserStatus.ACTIVE },
      }),
      this.appUserRepository.count({
        where: { status: AppUserStatus.INACTIVE },
      }),
      this.appUserRepository.count({
        where: {
          createdAt: new Date(new Date().setHours(0, 0, 0, 0)),
        },
      }),
    ]);

    // 제공자별 통계
    const providerStats = await this.appUserRepository
      .createQueryBuilder('user')
      .select('user.provider', 'provider')
      .addSelect('COUNT(*)', 'count')
      .where('user.status = :status', { status: AppUserStatus.ACTIVE })
      .groupBy('user.provider')
      .getRawMany();

    // 성별 통계
    const genderStats = await this.appUserRepository
      .createQueryBuilder('user')
      .select('user.gender', 'gender')
      .addSelect('COUNT(*)', 'count')
      .where('user.status = :status', { status: AppUserStatus.ACTIVE })
      .groupBy('user.gender')
      .getRawMany();

    // 최근 7일 신규 가입자 수
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
    const newUsersWeek = await this.appUserRepository.count({
      where: {
        createdAt: sevenDaysAgo,
        status: AppUserStatus.ACTIVE,
      },
    });

    return {
      totalUsers,
      activeUsers,
      inactiveUsers,
      newUsersToday,
      newUsersWeek,
      providerStats,
      genderStats,
      retentionRate: totalUsers > 0 ? ((activeUsers / totalUsers) * 100).toFixed(2) + '%' : '0%',
    };
  }

  // 🆕 사용자 ID로 조회 (관리자용)
  async getUserById(userId: number): Promise<AppUser | null> {
    return this.appUserRepository.findOne({
      where: { id: userId },
    });
  }

  // 🆕 닉네임으로 사용자 검색 (관리자용)
  async searchUsersByNickname(nickname: string): Promise<AppUser[]> {
    return this.appUserRepository.find({
      where: { 
        nickname: nickname,
        status: AppUserStatus.ACTIVE,
      },
    });
  }

  // 🆕 이메일로 사용자 검색 (관리자용)
  async searchUsersByEmail(email: string): Promise<AppUser[]> {
    return this.appUserRepository.find({
      where: { 
        email: email,
        status: AppUserStatus.ACTIVE,
      },
    });
  }
}