// src/auth/strategies/google.strategy.ts
import { Inject, Injectable, Logger } from '@nestjs/common';
import { ConfigType } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { InjectRepository } from '@nestjs/typeorm';
import { appConfiguration } from 'configuration';
import { User } from 'entities/user.entity';
import {
  Profile,
  Strategy,
  StrategyOptions,
  VerifyCallback,
} from 'passport-google-oauth20';
import { Repository } from 'typeorm';

export interface TransformedGoogleProfile {
  provider: 'google';
  providerId: string;
  email: string;
  name: string;
  picture?: string;
  accessToken: string;
  refreshToken?: string;
  googleProfileJson: Record<string, any>;
}

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  private readonly logger = new Logger(GoogleStrategy.name);

  constructor(
    @Inject(appConfiguration.KEY)
    private readonly appConfig: ConfigType<typeof appConfiguration>,
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
  ) {
    const clientID = appConfig.google.clientID;
    const clientSecret = appConfig.google.clientSecret;
    const callbackURL = appConfig.google.callbackURL;

    if (!clientID || !clientSecret || !callbackURL) {
      const errorMessage =
        'Google OAuth Strategy: CRITICAL ERROR - Missing clientID, clientSecret, or callbackURL in configuration. Ensure these are set in your .env file. Application cannot initialize Google OAuth properly.';
      console.error(errorMessage);
      throw new Error(errorMessage);
    }

    const strategyOptions: StrategyOptions = {
      clientID,
      clientSecret,
      callbackURL,
      scope: ['profile', 'email'],
      passReqToCallback: false,
    };

    super(strategyOptions);

    this.logger.log(
      `GoogleStrategy initialized. ClientID starts with: ${clientID.substring(
        0,
        10,
      )}...`,
    );
    this.logger.log(`CallbackURL: ${callbackURL}`);
  }

  validate(
    accessToken: string,
    refreshToken: string | undefined,
    profile: Profile,
    done: VerifyCallback,
  ): any {
    const { id, name, emails, photos, _json } = profile;
    this.logger.debug(
      `Validating Google profile for: ${emails?.[0]?.value || id}`,
    );

    if (!emails || emails.length === 0 || !emails[0].value) {
      this.logger.error('No email found in Google profile.', { profileId: id });
      return done(new Error('No email found in Google profile.'), false);
    }

    const transformedUser: TransformedGoogleProfile = {
      provider: 'google',
      providerId: id,
      email: emails[0].value,
      name: name
        ? `${name.givenName || ''} ${name.familyName || ''}`.trim()
        : emails[0].value.split('@')[0],
      picture: photos && photos.length > 0 ? photos[0].value : undefined,
      accessToken,
      refreshToken,
      googleProfileJson: _json,
    };

    done(null, transformedUser);
  }
}
