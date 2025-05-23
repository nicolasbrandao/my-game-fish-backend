/* eslint-disable @typescript-eslint/no-unused-vars */
import {
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Inject,
  Logger,
  Post,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { ConfigType } from '@nestjs/config';
import { appConfiguration } from 'configuration';
import { User } from 'entities/user.entity';
import { Request, Response } from 'express';
import { AuthService } from './auth.service';
import { GoogleOauthGuard } from './guards/google-oauth.guard';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { TransformedGoogleProfile } from './strategies/google.strategy';

@Controller('auth')
export class AuthController {
  private readonly logger = new Logger(AuthController.name);

  constructor(
    private readonly authService: AuthService,
    @Inject(appConfiguration.KEY)
    private readonly appConfig: ConfigType<typeof appConfiguration>,
  ) {}

  @Get('google')
  @UseGuards(GoogleOauthGuard)
  googleLogin() {
    this.logger.log('Initiating Google OAuth login');
  }

  @Get('google/callback')
  @UseGuards(GoogleOauthGuard)
  async googleLoginCallback(@Req() req: Request, @Res() res: Response) {
    this.logger.log('Received Google OAuth callback');

    if (!req.user) {
      this.logger.error(
        'User object not found in request after Google OAuth callback.',
      );
      const errorRedirectUrl = `${this.appConfig.FRONTEND_URL}/login?error=authentication_failed&message=User_information_not_available_after_Google_login`;
      return res.redirect(errorRedirectUrl);
    }

    try {
      const googleUser = req.user as TransformedGoogleProfile;
      this.logger.log(`Processing user from Google: ${googleUser.email}`);

      const { jwtToken } = await this.authService.handleGoogleLogin(googleUser);

      res.cookie('access_token', jwtToken, {
        httpOnly: true,
        secure: this.appConfig.NODE_ENV === 'production',
        path: '/',
        sameSite: 'lax',
      });

      this.logger.log(
        `JWT cookie set. Redirecting to frontend: ${this.appConfig.FRONTEND_URL}`,
      );
      res.redirect(this.appConfig.FRONTEND_URL || '/');
    } catch (error) {
      let errorMessage = 'An unexpected error occurred during login.';
      let errorStack: string | undefined;

      if (error instanceof Error) {
        errorMessage = error.message;
        errorStack = error.stack;
        this.logger.error(
          `Error during Google OAuth callback processing: ${errorMessage}`,
          errorStack,
        );
      } else {
        const unknownError = String(error);
        this.logger.error(
          `An unexpected non-Error type was thrown during Google OAuth callback processing: ${unknownError}`,
        );
        errorMessage = unknownError;
      }

      const errorQueryParam = encodeURIComponent(errorMessage);
      const errorRedirectUrl = `${this.appConfig.FRONTEND_URL}/login?error=${errorQueryParam}`;
      res.redirect(errorRedirectUrl);
    }
  }

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  getProfile(
    @Req() req: Request,
  ): Omit<
    User,
    'googleAccessToken' | 'googleRefreshToken' | 'googleProfileJson'
  > {
    this.logger.log(
      `User profile requested for user ID: ${(req.user as User).id}`,
    );
    const user = req.user as User;

    const {
      googleAccessToken,
      googleRefreshToken,
      googleProfileJson,
      ...safeUser
    } = user;
    return safeUser;
  }

  @Post('logout')
  @HttpCode(HttpStatus.OK)
  logout(@Res({ passthrough: true }) res: Response) {
    this.logger.log('Logout requested.');
    res.clearCookie('access_token', {
      httpOnly: true,
      secure: this.appConfig.NODE_ENV === 'production',
      path: '/',
      sameSite: 'lax',
    });

    return { message: 'Successfully logged out' };
  }
}
