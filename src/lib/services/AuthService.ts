import { supabase } from '@/lib/supabase';
import { TokenService } from './TokenService';
import { AuditService } from './AuditService';
import { AuthError, AUTH_ERROR_CODES } from '@/lib/utils/errors';
import { hashPassword } from '@/lib/utils/crypto';
import type { AuthResponse, UserSession } from '@/lib/types/auth';
import type { LoginInput, SignUpInput } from '@/lib/validation/auth';

export class AuthService {
  static async login({ email, password, deviceInfo }: LoginInput): Promise<AuthResponse> {
    try {
      // Hash password for comparison
      const passwordHash = await hashPassword(password);

      // Get user with plan information
      const { data: user, error: userError } = await supabase
        .from('users')
        .select(`
          id,
          email,
          firstname,
          lastname,
          password_hash,
          role,
          is_verified,
          plan_id
        `)
        .eq('email', email.toLowerCase())
        .single();

      if (userError || !user) {
        await AuditService.logAuthEvent('LOGIN_FAILED', {
          email,
          reason: 'User not found'
        });
        throw new AuthError(
          'Invalid email or password',
          AUTH_ERROR_CODES.INVALID_CREDENTIALS
        );
      }

      // Verify password
      if (user.password_hash !== passwordHash) {
        await AuditService.logAuthEvent('LOGIN_FAILED', {
          email,
          reason: 'Invalid password'
        });
        throw new AuthError(
          'Invalid email or password',
          AUTH_ERROR_CODES.INVALID_CREDENTIALS
        );
      }

      // Generate tokens
      const tokens = TokenService.generateTokens({
        userId: user.id,
        email: user.email,
        role: user.role || 'user',
        planId: user.plan_id
      }, deviceInfo);

      // Save refresh token
      await this.saveRefreshToken(user.id, tokens.refreshToken, deviceInfo);

      // Log successful login
      await AuditService.logAuthEvent('LOGIN_SUCCESS', {
        userId: user.id,
        email: user.email
      });

      // Update last login timestamp
      await supabase
        .from('users')
        .update({ last_login: new Date().toISOString() })
        .eq('id', user.id);

      return {
        user: {
          id: user.id,
          email: user.email,
          firstName: user.firstname,
          lastName: user.lastname,
          role: user.role || 'user',
          isVerified: user.is_verified,
          planId: user.plan_id
        },
        tokens
      };
    } catch (error) {
      console.error('Login error:', error);
      if (error instanceof AuthError) {
        throw error;
      }
      throw new AuthError(
        'Failed to log in',
        AUTH_ERROR_CODES.SERVER_ERROR,
        { originalError: error }
      );
    }
  }

  static async signUp({ email, password, firstName, lastName, deviceInfo }: SignUpInput): Promise<AuthResponse> {
    try {
      // Check if email already exists
      const { data: existingUser } = await supabase
        .from('users')
        .select('id')
        .eq('email', email)
        .single();

      if (existingUser) {
        throw new AuthError(
          'Email already exists',
          AUTH_ERROR_CODES.EMAIL_EXISTS
        );
      }

      // Hash password
      const passwordHash = await hashPassword(password);

      // First, verify that the Unpaid plan exists
      const { data: planData, error: planError } = await supabase
        .from('plans')
        .select('id')
        .eq('name', 'Unpaid')
        .single();

      if (planError || !planData) {
        console.error('Plan lookup error:', planError);
        throw new AuthError(
          'Service configuration error',
          AUTH_ERROR_CODES.SERVER_ERROR,
          { originalError: planError }
        );
      }

      // Create user with default "Unpaid" plan
      const { data: userData, error: userError } = await supabase
        .rpc('create_user_with_plan', {
          p_email: email.toLowerCase(),
          p_firstname: firstName.trim(),
          p_lastname: lastName.trim(),
          p_password_hash: passwordHash,
          p_plan_name: 'Unpaid'
        });

      if (userError) {
        console.error('Create user error:', userError);
        throw new AuthError(
          'Failed to create user',
          AUTH_ERROR_CODES.SERVER_ERROR,
          { originalError: userError }
        );
      }

      if (!userData || userData.length === 0) {
        throw new AuthError(
          'User creation failed',
          AUTH_ERROR_CODES.SERVER_ERROR
        );
      }

      const user = userData[0];

      // Generate tokens
      const tokens = TokenService.generateTokens({
        userId: user.id,
        email: user.email,
        role: user.role || 'user',
        planId: planData.id
      }, deviceInfo);

      // Save refresh token
      await this.saveRefreshToken(user.id, tokens.refreshToken, deviceInfo);

      // Log successful signup
      await AuditService.logAuthEvent('SIGNUP_SUCCESS', {
        userId: user.id,
        email: user.email
      });

      return {
        user: {
          id: user.id,
          email: user.email,
          firstName: user.firstname,
          lastName: user.lastname,
          role: user.role || 'user',
          isVerified: false,
          planId: planData.id
        },
        tokens
      };
    } catch (error) {
      console.error('Signup error:', error);
      if (error instanceof AuthError) {
        throw error;
      }
      throw new AuthError(
        'Failed to create account',
        AUTH_ERROR_CODES.SERVER_ERROR,
        { originalError: error }
      );
    }
  }

  private static async saveRefreshToken(userId: number, token: string, deviceInfo?: string): Promise<void> {
    const { error } = await supabase
      .from('refresh_tokens')
      .insert({
        user_id: userId,
        token,
        device_info: deviceInfo,
        expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days
      });

    if (error) {
      console.error('Failed to save refresh token:', error);
    }
  }
}