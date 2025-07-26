// src/modules/betsapi/controllers/enhanced-betsapi.controller.ts (수정된 버전)
import { Controller, Get, Post, Query, Param, Body } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiQuery, ApiParam, ApiBody } from '@nestjs/swagger';
import { IsArray, IsString, IsBoolean, IsOptional } from 'class-validator';
import { 
  EnhancedBetsApiService, 
  SelectiveSyncOptions, 
  SelectiveSyncResult // export된 인터페이스 import
} from '../services/enhanced-betsapi.service';
import { FootballMatchesService } from '../../football-matches/services/football-matches.service';
import { MatchType } from '../types/betsapi.types';
import { EnhancedMatchResponse } from '../../football-matches/types/football-match.types';

// 선택적 동기화 DTO
class SelectiveSyncDto {
  @IsArray()
  @IsString({ each: true })
  eventIds: string[];

  @IsOptional()
  options?: {
    forceOverwrite?: boolean;
    statsOnly?: boolean;
    dateFilter?: string;
    matchType?: string;
  };
}

@ApiTags('Enhanced BetsAPI - Complete Football Data Management')
@Controller('/api/v1/enhanced-football')
export class EnhancedBetsApiController {
  constructor(
    private readonly enhancedBetsApiService: EnhancedBetsApiService,
    private readonly footballMatchesService: FootballMatchesService,
  ) {}

  // ======================
  // 기본 경기 조회 API
  // ======================

  @Get('matches/upcoming')
  @ApiOperation({
    summary: 'DB 저장된 예정 경기 조회 (완전한 데이터)',
    description: 'MongoDB에 저장된 예정 축구 경기를 모든 통계와 함께 조회합니다.',
  })
  @ApiResponse({ 
    status: 200, 
    description: 'DB 저장된 예정 경기 목록이 성공적으로 조회되었습니다.',
  })
  @ApiQuery({
    name: 'page',
    required: false,
    type: Number,
    default: 1,
    description: 'Page number for pagination',
  })
  @ApiQuery({
    name: 'day',
    required: false,
    type: String,
    description: 'Filter by specific day (YYYYMMDD format)',
  })
  async getEnhancedUpcomingMatches(
    @Query('page') page: number = 1,
    @Query('day') day?: string,
  ): Promise<{ success: boolean; data: EnhancedMatchResponse; message: string }> {
    const matches = await this.enhancedBetsApiService.getEnhancedMatches(
      'upcoming', 
      Number(page), 
      day
    );
    
    return {
      success: true,
      data: matches,
      message: 'Complete upcoming matches data retrieved from MongoDB'
    };
  }

  @Get('matches/inplay')
  @ApiOperation({
    summary: 'DB 저장된 진행중 경기 조회 (실시간 통계 포함)',
    description: 'MongoDB에 저장된 진행 중인 축구 경기를 실시간 통계와 함께 조회합니다.',
  })
  @ApiResponse({ 
    status: 200, 
    description: 'DB 저장된 진행중 경기 목록이 성공적으로 조회되었습니다.',
  })
  async getEnhancedInplayMatches(): Promise<{ success: boolean; data: EnhancedMatchResponse; message: string }> {
    const matches = await this.enhancedBetsApiService.getEnhancedMatches('inplay', 1);
    
    return {
      success: true,
      data: matches,
      message: 'Complete inplay matches data with live stats retrieved from MongoDB'
    };
  }

  @Get('matches/ended')
  @ApiOperation({
    summary: 'DB 저장된 종료 경기 조회 (최종 통계 포함)',
    description: 'MongoDB에 저장된 종료된 축구 경기를 최종 통계와 함께 조회합니다.',
  })
  @ApiResponse({ 
    status: 200, 
    description: 'DB 저장된 종료 경기 목록이 성공적으로 조회되었습니다.',
  })
  @ApiQuery({
    name: 'page',
    required: false,
    type: Number,
    default: 1,
    description: 'Page number for pagination',
  })
  @ApiQuery({
    name: 'day',
    required: false,
    type: String,
    description: 'Filter by specific day (YYYYMMDD format)',
  })
  async getEnhancedEndedMatches(
    @Query('page') page: number = 1,
    @Query('day') day?: string,
  ): Promise<{ success: boolean; data: EnhancedMatchResponse; message: string }> {
    const matches = await this.enhancedBetsApiService.getEnhancedMatches(
      'ended', 
      Number(page), 
      day
    );
    
    return {
      success: true,
      data: matches,
      message: 'Complete ended matches data with final stats retrieved from MongoDB'
    };
  }

  @Get('match/:eventId')
  @ApiOperation({
    summary: 'DB 저장된 경기 상세 조회 (모든 통계 포함)',
    description: 'MongoDB에 저장된 특정 경기의 모든 상세 정보와 통계를 조회합니다.',
  })
  @ApiResponse({ 
    status: 200, 
    description: 'DB 저장된 경기 상세 정보가 성공적으로 조회되었습니다.',
  })
  @ApiParam({
    name: 'eventId',
    type: String,
    description: 'BetsAPI Event ID',
    example: '10150692',
  })
  async getEnhancedMatchDetails(@Param('eventId') eventId: string) {
    const matchDetails = await this.enhancedBetsApiService.getEnhancedMatchDetails(eventId);
    return {
      success: true,
      data: matchDetails,
      message: 'Complete match details with all statistics retrieved from MongoDB'
    };
  }

  // ======================
  // 🔧 수정된 동기화 API
  // ======================

  @Post('sync/auto/:type')
  @ApiOperation({
      summary: 'BetsAPI → MongoDB 스마트 동기화 (토글 상태 고려)',
      description: 'BetsAPI에서 특정 타입의 경기를 가져와 MongoDB에 저장하되, 동기화 허용 토글이 꺼진 경기는 건드리지 않습니다.',
  })
  @ApiResponse({ 
      status: 200, 
      description: 'BetsAPI → MongoDB 스마트 동기화가 성공적으로 완료되었습니다.',
  })
  @ApiParam({
      name: 'type',
      enum: ['upcoming', 'inplay', 'ended'],
      description: 'Match type to sync from BetsAPI',
      example: 'upcoming',
  })
  @ApiQuery({
      name: 'day',
      required: false,
      type: String,
      description: 'Specific day to sync (YYYYMMDD format)',
  })
  async autoSync(
      @Param('type') type: MatchType,
      @Query('day') day?: string,
      @Body() body?: any, // 🔧 수정: body 파라미터 추가 (빈 객체 허용)
  ) {
      try {
          console.log(`🔄 스마트 동기화 요청 - Type: ${type}, Day: ${day}`);
          
          // 🔧 수정: 입력 검증 강화
          if (!['upcoming', 'inplay', 'ended'].includes(type)) {
              return {
                  success: false,
                  message: '올바르지 않은 경기 타입입니다.',
                  error: 'INVALID_MATCH_TYPE'
              };
          }

          const result = await this.enhancedBetsApiService.smartAutoSync(type, day);
          
          return {
              success: true,
              data: result,
              message: `스마트 동기화 완료: ${result.created}개 생성, ${result.updated}개 업데이트, ${result.skipped}개 건너뜀 (동기화 차단됨)`
          };
      } catch (error) {
          console.error('❌ 동기화 실패:', error);
          
          // 🔧 수정: 에러 응답 구조 개선
          return {
              success: false,
              data: {
                  created: 0,
                  updated: 0,
                  skipped: 0,
                  errors: 1,
                  details: [error.message]
              },
              message: `동기화 실패: ${error.message}`,
              error: 'SYNC_FAILED'
          };
      }
  }

  @Post('sync/selective')
  @ApiOperation({
    summary: '선택적 경기 동기화',
    description: '선택된 경기들만 BetsAPI에서 가져와 MongoDB에 동기화합니다.',
  })
  @ApiResponse({ 
    status: 200, 
    description: '선택적 동기화가 성공적으로 완료되었습니다.',
  })
  @ApiBody({ 
    type: SelectiveSyncDto,
    description: '동기화할 경기 ID 목록과 옵션들',
    examples: {
      example1: {
        summary: '기본 동기화',
        value: {
          eventIds: ['10150692', '10150693', '10150694'],
          options: {
            forceOverwrite: true,
            statsOnly: false,
            dateFilter: '20250122',
            matchType: 'upcoming'
          }
        }
      }
    }
  })
  async selectiveSync(@Body() selectiveSyncDto: SelectiveSyncDto): Promise<{
    success: boolean;
    data: SelectiveSyncResult;
    message: string;
  }> {
    const { eventIds, options = {} } = selectiveSyncDto;
    
    console.log(`🎯 선택적 동기화 시작 - ${eventIds.length}개 경기`);
    console.log('📋 동기화 옵션:', options);
    
    try {
      const result = await this.enhancedBetsApiService.selectiveSync(eventIds, options);
      
      return {
        success: true,
        data: result,
        message: `선택적 동기화 완료: ${result.updated}개 업데이트, ${result.created}개 생성, ${result.errors}개 오류`
      };
    } catch (error) {
      console.error('❌ 선택적 동기화 실패:', error);
      throw error;
    }
  }

  @Post('sync/full')
  @ApiOperation({
    summary: 'BetsAPI → MongoDB 전체 스마트 동기화',
    description: 'BetsAPI에서 오늘과 내일의 모든 경기를 가져와 MongoDB에 저장하되, 동기화 차단된 경기는 보호합니다.',
  })
  @ApiResponse({ 
    status: 200, 
    description: 'BetsAPI → MongoDB 전체 스마트 동기화가 성공적으로 완료되었습니다.',
  })
  async fullSync() {
    const result = await this.enhancedBetsApiService.smartFullSync();
    return {
      success: true,
      data: result,
      message: `전체 스마트 동기화 완료: ${result.total.created}개 총 생성, ${result.total.updated}개 총 업데이트, ${result.total.skipped}개 총 건너뜀`
    };
  }

  @Post('sync/resync-incomplete')
  @ApiOperation({
    summary: '불완전한 데이터 재동기화',
    description: '통계나 기타 데이터가 누락된 경기들을 재동기화합니다.',
  })
  @ApiResponse({ 
    status: 200, 
    description: '불완전한 데이터 재동기화가 완료되었습니다.',
  })
  async resyncIncomplete() {
    const result = await this.footballMatchesService.resyncIncompleteMatches();
    return {
      success: true,
      data: result,
      message: `불완전 데이터 재동기화 완료: ${result.resynced}개 재동기화, ${result.errors}개 오류`
    };
  }

  // ======================
  // 통계 및 분석 API
  // ======================

  @Get('stats/db')
  @ApiOperation({
    summary: 'MongoDB 저장된 경기 통계',
    description: 'MongoDB에 저장된 경기들의 통계를 조회합니다.',
  })
  @ApiResponse({ 
    status: 200, 
    description: 'MongoDB 경기 통계가 성공적으로 조회되었습니다.',
  })
  async getDbStats() {
    const stats = await this.enhancedBetsApiService.getDbMatchesCount();
    return {
      success: true,
      data: stats,
      message: 'MongoDB match statistics retrieved successfully'
    };
  }

  @Get('stats/completeness')
  @ApiOperation({
    summary: '데이터 완성도 분석',
    description: '저장된 경기 데이터의 완성도를 분석합니다.',
  })
  @ApiResponse({ 
    status: 200, 
    description: '데이터 완성도 분석이 성공적으로 완료되었습니다.',
  })
  async getDataCompleteness() {
    const analysis = await this.footballMatchesService.checkDataCompleteness();
    return {
      success: true,
      data: analysis,
      message: 'Data completeness analysis completed successfully'
    };
  }

  @Get('match/:matchId/stats/detailed')
  @ApiOperation({
    summary: '경기 상세 통계 분석',
    description: '특정 경기의 상세 통계를 분석하여 인사이트를 제공합니다.',
  })
  @ApiResponse({ 
    status: 200, 
    description: '경기 상세 통계 분석이 성공적으로 완료되었습니다.',
  })
  @ApiParam({
    name: 'matchId',
    type: String,
    description: 'MongoDB Match ID',
    example: '507f1f77bcf86cd799439011',
  })
  async getDetailedMatchStats(@Param('matchId') matchId: string) {
    const analysis = await this.footballMatchesService.getDetailedMatchStats(matchId);
    return {
      success: true,
      data: analysis,
      message: 'Detailed match statistics analysis completed successfully'
    };
  }

  @Get('match/:matchId/quality')
  @ApiOperation({
    summary: '경기 품질 평가',
    description: '경기의 재미도와 품질을 평가합니다.',
  })
  @ApiResponse({ 
    status: 200, 
    description: '경기 품질 평가가 성공적으로 완료되었습니다.',
  })
  @ApiParam({
    name: 'matchId',
    type: String,
    description: 'MongoDB Match ID',
    example: '507f1f77bcf86cd799439011',
  })
  async assessMatchQuality(@Param('matchId') matchId: string) {
    const assessment = await this.footballMatchesService.assessMatchQuality(matchId);
    return {
      success: true,
      data: assessment,
      message: 'Match quality assessment completed successfully'
    };
  }

  // ======================
  // 고급 쿼리 API
  // ======================

  @Get('matches/high-quality')
  @ApiOperation({
    summary: '고품질 경기 조회',
    description: '통계적으로 재미있고 품질이 높은 경기들을 조회합니다.',
  })
  @ApiResponse({ 
    status: 200, 
    description: '고품질 경기 목록이 성공적으로 조회되었습니다.',
  })
  @ApiQuery({
    name: 'limit',
    required: false,
    type: Number,
    default: 20,
    description: 'Number of matches to return',
  })
  async getHighQualityMatches(@Query('limit') limit: number = 20) {
    // 고품질 경기 필터링 로직 (예: 많은 골, 높은 xG, 균형잡힌 경기)
    const matches = await this.footballMatchesService.getAll({ skip: 0, limit: 100 });
    
    // 여기서 품질 기준으로 필터링
    const qualityMatches = matches.results.filter(match => {
      if (!match.stats) return false;
      
      const totalGoals = parseInt(match.stats.goals?.[0] || '0') + parseInt(match.stats.goals?.[1] || '0');
      const totalShots = parseInt(match.stats.goalattempts?.[0] || '0') + parseInt(match.stats.goalattempts?.[1] || '0');
      
      return totalGoals >= 3 || totalShots >= 20; // 3골 이상 또는 20슛 이상
    }).slice(0, limit);

    return {
      success: true,
      data: {
        results: qualityMatches,
        criteria: 'Matches with 3+ goals or 20+ shots',
        count: qualityMatches.length,
      },
      message: 'High quality matches retrieved successfully'
    };
  }

  @Get('matches/with-stats/:statType')
  @ApiOperation({
    summary: '특정 통계가 있는 경기 조회',
    description: '특정 통계 데이터가 있는 경기들만 조회합니다.',
  })
  @ApiResponse({ 
    status: 200, 
    description: '특정 통계가 있는 경기 목록이 성공적으로 조회되었습니다.',
  })
  @ApiParam({
    name: 'statType',
    enum: ['xg', 'possession', 'shots', 'cards'],
    description: 'Type of statistics to filter by',
    example: 'xg',
  })
  @ApiQuery({
    name: 'limit',
    required: false,
    type: Number,
    default: 50,
    description: 'Number of matches to return',
  })
  async getMatchesWithStats(
    @Param('statType') statType: string,
    @Query('limit') limit: number = 50,
  ) {
    const matches = await this.footballMatchesService.getAll({ skip: 0, limit: 200 });
    
    const filteredMatches = matches.results.filter(match => {
      if (!match.stats) return false;
      
      switch (statType) {
        case 'xg':
          return match.stats.xg && match.stats.xg[0] && match.stats.xg[1];
        case 'possession':
          return match.stats.possession_rt && match.stats.possession_rt[0] && match.stats.possession_rt[1];
        case 'shots':
          return match.stats.goalattempts && match.stats.goalattempts[0] && match.stats.goalattempts[1];
        case 'cards':
          return match.stats.yellowcards || match.stats.redcards;
        default:
          return false;
      }
    }).slice(0, limit);

    return {
      success: true,
      data: {
        results: filteredMatches,
        statType,
        count: filteredMatches.length,
      },
      message: `Matches with ${statType} statistics retrieved successfully`
    };
  }

  // ======================
  // 🔧 수정된 동기화 상태 체크
  // ======================

  @Get('check/sync-needed')
  @ApiOperation({
    summary: '동기화 필요 여부 확인',
    description: 'MongoDB에 데이터가 있는지 확인하여 동기화가 필요한지 알려줍니다.',
  })
  @ApiResponse({ 
    status: 200, 
    description: '동기화 필요 여부가 성공적으로 확인되었습니다.',
  })
  async checkSyncNeeded() {
    try {
      const dbStats = await this.enhancedBetsApiService.getDbMatchesCount();
      let completeness = { completeness_percentage: 0 };
      
      // 🔧 수정: completeness 체크 시 에러 처리
      try {
        completeness = await this.footballMatchesService.checkDataCompleteness();
      } catch (error) {
        console.warn('⚠️ 완성도 체크 실패, 기본값 사용:', error.message);
      }
      
      const syncNeeded = dbStats.total === 0;
      const incompleteData = completeness.completeness_percentage < 80;
      
      let recommendation = '';
      if (syncNeeded) {
        recommendation = 'MongoDB에 데이터가 없습니다. "동기화"를 실행하여 BetsAPI에서 완전한 데이터를 가져오세요.';
      } else if (incompleteData) {
        recommendation = `데이터 완성도가 ${completeness.completeness_percentage}%입니다. 동기화를 실행하여 데이터를 보완하세요.`;
      } else if (dbStats.upcoming === 0) {
        recommendation = '예정된 경기가 없습니다. "동기화"를 실행하여 최신 경기를 가져오세요.';
      } else {
        recommendation = 'MongoDB에 충분하고 완전한 데이터가 있습니다.';
      }
      
      return {
        success: true,
        data: {
          syncNeeded,
          incompleteData,
          dbStats,
          completeness: completeness.completeness_percentage,
          recommendation,
        },
        message: 'Sync requirement and data completeness check completed'
      };
    } catch (error) {
      console.error('❌ 동기화 상태 체크 실패:', error);
      
      // 🔧 수정: 에러 발생 시 기본 응답 반환
      return {
        success: true,
        data: {
          syncNeeded: true,
          incompleteData: true,
          dbStats: { upcoming: 0, inplay: 0, ended: 0, total: 0 },
          completeness: 0,
          recommendation: '상태 확인 중 오류가 발생했습니다. "동기화"를 실행하여 데이터를 가져오세요.',
        },
        message: 'Sync status check completed with fallback data'
      };
    }
  }

  @Get('debug/sample-data')
  @ApiOperation({
    summary: '샘플 데이터 확인 (디버깅용)',
    description: '저장된 데이터의 샘플을 확인하여 스키마와 내용을 검증합니다.',
  })
  @ApiResponse({ 
    status: 200, 
    description: '샘플 데이터가 성공적으로 조회되었습니다.',
  })
  async getSampleData() {
    const matches = await this.footballMatchesService.getAll({ skip: 0, limit: 3 });
    
    const sampleAnalysis = {
      total_matches: matches.totalCount,
      sample_count: matches.results.length,
      samples: matches.results.map(match => ({
        betsApiId: match.betsApiId,
        homeTeam: match.home.name,
        awayTeam: match.away.name,
        hasStats: !!match.stats,
        statsFields: match.stats ? Object.keys(match.stats).length : 0,
        hasXG: !!(match.stats?.xg),
        hasPossession: !!(match.stats?.possession_rt),
        hasOTeams: !!(match.o_home || match.o_away),
        dataSource: match.dataSource,
        lastSyncAt: match.lastSyncAt,
        allowSync: match.allowSync, // 🆕 동기화 허용 상태 추가
      })),
    };

    return {
      success: true,
      data: sampleAnalysis,
      message: 'Sample data analysis completed for debugging'
    };
  }
}