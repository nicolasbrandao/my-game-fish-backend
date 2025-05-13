// src/auth/auth.service.ts
import {
  Injectable,
  InternalServerErrorException,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from 'entities/user.entity';
import { Repository } from 'typeorm';
import { TransformedGoogleProfile } from './strategies/google.strategy';

export interface JwtPayload {
  sub: string;
  email: string;
  roles?: string[];
  username?: string;
  iat?: number;
  exp?: number;
}

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly jwtService: JwtService,
  ) {}

  async handleGoogleLogin(
    googleUserData: TransformedGoogleProfile,
  ): Promise<{ jwtToken: string; user: User }> {
    if (!googleUserData || !googleUserData.email) {
      this.logger.error(
        'Invalid or incomplete user data from Google strategy.',
        { dataReceived: googleUserData },
      );
      throw new UnauthorizedException(
        'Authentication failed due to incomplete user data from provider.',
      );
    }

    const {
      providerId,
      email,
      name,
      accessToken,
      refreshToken,
      googleProfileJson,
    } = googleUserData;
    this.logger.log(
      `Processing Google login for email: ${email} (Provider ID: ${providerId})`,
    );

    try {
      let user = await this.userRepository.findOne({ where: { email } });

      if (user) {
        this.logger.log(`User ${email} found. Updating Google details.`);
        user.googleId = providerId;
        user.displayName = name || user.displayName;
        user.googleAccessToken = accessToken;
        user.googleRefreshToken = refreshToken || user.googleRefreshToken;
        user.googleProfileJson = googleProfileJson;
      } else {
        this.logger.log(`User ${email} not found. Creating new user.`);
        user = this.userRepository.create({
          email,
          googleId: providerId,
          displayName: name || email.split('@')[0],
          googleAccessToken: accessToken,
          googleRefreshToken: refreshToken,
          googleProfileJson,
        });
      }

      const savedUser = await this.userRepository.save(user);
      this.logger.log(`User details saved/updated for ID: ${savedUser.id}`);

      const jwtApiPayload: JwtPayload = {
        sub: savedUser.id,
        email: savedUser.email,
      };
      const jwtToken = await this.jwtService.signAsync(jwtApiPayload);
      this.logger.log(`JWT generated for user ID: ${savedUser.id}`);

      return { jwtToken, user: savedUser };
    } catch (error) {
      this.logger.error(
        `Error during Google login processing for ${email}: ${error}`,
      );
      throw new InternalServerErrorException(
        'An error occurred while processing your login with Google.',
      );
    }
  }
}
