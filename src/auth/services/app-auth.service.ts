// src/auth/services/app-auth.service.ts (TypeORM 타입 에러 수정 버전)
import { Injectable, UnauthorizedException, BadRequestException, ConflictException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { JwtService } from '@nestjs/jwt';

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
  isNewUser: boolean;
}

@Injectable()
export class AppAuthService {
  constructor(
    @InjectRepository(AppUser)
    private appUserRepository: Repository<AppUser>,
    private jwtService: JwtService,
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
      refreshToken,
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
        nickname: nickname || name, // 닉네임이 없으면 이름 사용
        profileImageUrl,
        birthDate: birthDate ? new Date(birthDate) : undefined,
        gender,
        phoneNumber,
        status: AppUserStatus.ACTIVE,
        refreshToken,
        tokenExpiresAt: refreshToken ? new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) : undefined, // 30일
      });

      user = await this.appUserRepository.save(user);
      isNewUser = true;
    } else {
      // 기존 사용자 정보 업데이트
      await this.appUserRepository.update(user.id, {
        email: email || user.email,
        name: name || user.name,
        // 닉네임은 사용자가 명시적으로 변경하지 않는 한 유지
        nickname: user.nickname || nickname || name,
        profileImageUrl: profileImageUrl || user.profileImageUrl,
        birthDate: birthDate ? new Date(birthDate) : user.birthDate,
        gender: gender || user.gender,
        phoneNumber: phoneNumber || user.phoneNumber,
        lastLoginAt: new Date(),
        lastLoginIp: clientIp,
        refreshToken: refreshToken || user.refreshToken,
        tokenExpiresAt: refreshToken ? new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) : user.tokenExpiresAt,
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

    // JWT 토큰 생성
    const accessToken = this.generateAccessToken(user);

    return {
      user,
      accessToken,
      isNewUser,
    };
  }

  // 🆕 닉네임 중복 검증
  async checkNicknameAvailability(nickname: string): Promise<boolean> {
    if (!nickname || nickname.trim().length === 0) {
      return false;
    }

    // 닉네임 길이 검증
    if (nickname.length < 2 || nickname.length > 20) {
      return false;
    }

    // 특수문자 검증 (한글, 영문, 숫자, 일부 특수문자만 허용)
    const nicknameRegex = /^[가-힣a-zA-Z0-9_.-]+$/;
    if (!nicknameRegex.test(nickname)) {
      return false;
    }

    // 금지어 검증 (필요시 추가)
    const forbiddenWords = ['admin', '관리자', 'null', 'undefined', 'test'];
    if (forbiddenWords.some(word => nickname.toLowerCase().includes(word.toLowerCase()))) {
      return false;
    }

    // 데이터베이스에서 중복 확인
    const existingUser = await this.appUserRepository.findOne({
      where: { nickname },
    });

    return !existingUser;
  }

  // 🔧 수정: 로그아웃 (토큰 무효화) - 타입 에러 해결
  async logout(userId: number): Promise<void> {
    await this.appUserRepository.update(userId, {
      refreshToken: undefined, // null 대신 undefined 사용
      tokenExpiresAt: undefined, // null 대신 undefined 사용
    });
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

    // 닉네임 변경 시 중복 검증
    if (updateData.nickname && updateData.nickname !== user.nickname) {
      const isNicknameAvailable = await this.checkNicknameAvailability(updateData.nickname);
      if (!isNicknameAvailable) {
        throw new ConflictException('이미 사용 중인 닉네임입니다.');
      }
    }

    // 업데이트 가능한 필드만 허용
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
    await this.appUserRepository.update(userId, {
      status: AppUserStatus.INACTIVE,
      refreshToken: undefined, // null 대신 undefined 사용
      tokenExpiresAt: undefined, // null 대신 undefined 사용
    });
  }

  async deleteUser(userId: number): Promise<void> {
    await this.appUserRepository.softDelete(userId);
  }

  private generateAccessToken(user: AppUser): string {
    const payload = {
      sub: user.id,
      email: user.email,
      type: 'app' as const,
      provider: user.provider,
      nickname: user.nickname,
    };

    return this.jwtService.sign(payload);
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