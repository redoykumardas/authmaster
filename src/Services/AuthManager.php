<?php

namespace Redoy\AuthMaster\Services;

use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Log;
use Redoy\AuthMaster\Contracts\AuthManagerInterface;
use Redoy\AuthMaster\Contracts\DeviceSessionServiceInterface;
use Redoy\AuthMaster\Contracts\PasswordServiceInterface;
use Redoy\AuthMaster\Contracts\SecurityServiceInterface;
use Redoy\AuthMaster\Contracts\SocialLoginServiceInterface;
use Redoy\AuthMaster\Contracts\TokenServiceInterface;
use Redoy\AuthMaster\Contracts\TwoFactorServiceInterface;
use Redoy\AuthMaster\Contracts\ValidationManagerInterface;
use Redoy\AuthMaster\DTOs\AuthResult;
use Redoy\AuthMaster\DTOs\LoginData;
use Redoy\AuthMaster\DTOs\PasswordResetData;
use Redoy\AuthMaster\Exceptions\AuthException;
use Redoy\AuthMaster\Exceptions\InvalidCredentialsException;
use Redoy\AuthMaster\Exceptions\TooManyAttemptsException;
use Redoy\AuthMaster\Exceptions\TwoFactorRequiredException;
use Redoy\AuthMaster\Events\LoginSuccessful;
use Redoy\AuthMaster\Events\LogoutSuccessful;

class AuthManager implements AuthManagerInterface
{
    protected $userModel;

    public function __construct(
        protected ValidationManagerInterface $validator,
        protected TokenServiceInterface $tokenService,
        protected DeviceSessionServiceInterface $deviceService,
        protected PasswordServiceInterface $passwordService,
        protected TwoFactorServiceInterface $twoFactorService,
        protected SecurityServiceInterface $securityService,
        protected SocialLoginServiceInterface $socialLoginService,
        protected Hasher $hasher
    ) {
        $this->userModel = config('auth.providers.users.model');
    }

    public function extractDeviceId(Request $request): string
    {
        $deviceId = $request->header('device_id')
            ?? $request->header('X-Device-Id')
            ?? $request->header('Device-Id');

        if ($deviceId) {
            return (string) $deviceId;
        }

        return hash('sha256', (string) $request->ip() . '|' . (string) $request->userAgent());
    }


    public function loginWithData(LoginData $data): AuthResult
    {
        $this->securityService->allowLoginAttempt($data->email, $data->ipAddress, $data->deviceId);

        if (!Auth::attempt(['email' => $data->email, 'password' => $data->password])) {
            $this->securityService->recordFailedAttempt($data->email, $data->ipAddress, $data->deviceId);
            throw new InvalidCredentialsException();
        }

        $user = Auth::user();

        if (config('authmaster.enable_2fa') && $this->twoFactorService->isTwoFactorRequiredFor($user)) {
            $otpCode = $this->twoFactorService->generateAndSend($user, $data->deviceId);
            
            $tempToken = $this->generateTempToken($user);
            throw new TwoFactorRequiredException('Two-factor authentication required', $tempToken, $otpCode);
        }

        $this->securityService->clearFailedAttempts($user->email);

        return $this->finalizeLoginFromData(
            $user,
            $data->deviceId,
            $data->deviceName,
            $data->ipAddress,
            $data->userAgent
        );
    }

    /**
     * Finalize the login process: create token, store session, and enforce limits.
     */

    /**
     * Finalize login using device data directly (for DTO-based flows).
     */
    public function finalizeLoginFromData($user, string $deviceId, ?string $deviceName = null, ?string $ipAddress = null, ?string $userAgent = null): AuthResult
    {
        $tokenData = $this->tokenService->createTokenForUser($user, $deviceId);

        $this->deviceService->createOrUpdateSessionFromData(
            $user,
            $deviceId,
            $tokenData['token_id'] ?? null,
            $tokenData,
            $deviceName,
            $ipAddress,
            $userAgent
        );

        $this->deviceService->enforceDeviceLimit($user);

        return (new AuthResult(
            user: $user,
            token: $tokenData,
            message: 'Logged in'
        ))->tap(fn($res) => event(new LoginSuccessful($user, $deviceId, $ipAddress)));
    }


    public function logoutCurrentDevice(Request $request): void
    {
        $deviceId = $this->extractDeviceId($request);
        $user = $request->user();
        if ($user) {
            $this->deviceService->invalidateSession($user, $deviceId);
            $this->securityService->clearFailedAttempts($user->email, $deviceId);
            event(new LogoutSuccessful($user, $deviceId));
        }
    }

    public function logoutAllDevices(Request $request): void
    {
        $user = $request->user();
        if ($user) {
            $this->deviceService->invalidateAllSessions($user);
            event(new LogoutSuccessful($user));
        }
    }

    public function updateProfile($user, array $data): AuthResult
    {
        $user->update($data);
        return new AuthResult(user: $user, message: 'Profile updated');
    }

    public function changePassword($user, array $payload): AuthResult
    {
        if (!$this->hasher->check($payload['current_password'], $user->password)) {
            throw new AuthException('Current password does not match', 422);
        }
        $user->update(['password' => $this->hasher->make($payload['password'])]);
        return new AuthResult(message: 'Password changed');
    }

    public function sendPasswordResetLink(array $payload): AuthResult
    {
        $this->passwordService->sendResetLink($payload['email']);
        return new AuthResult(message: 'Reset email sent');
    }


    public function resetPasswordWithData(PasswordResetData $data): AuthResult
    {
        $this->passwordService->resetPassword([
            'email' => $data->email,
            'password' => $data->password,
            'token' => $data->token,
        ]);

        return new AuthResult(message: 'Password reset');
    }

    public function sendTwoFactor($user): AuthResult
    {
        $this->twoFactorService->generateAndSend($user, null);
        return new AuthResult(message: 'OTP sent');
    }

    public function verifyTwoFactor($user, $code): AuthResult
    {
        $this->twoFactorService->verify($user, $code);
        return new AuthResult(message: 'OTP verified');
    }

    public function verifyTwoFactorLogin(string $tempToken, string $code, string $deviceId, ?string $deviceName, string $ipAddress, ?string $userAgent): AuthResult
    {
        // 1. Decrypt token to find user
        try {
            $payload = json_decode(Crypt::decryptString($tempToken), true);
        } catch (\Exception $e) {
            throw new AuthException('Invalid or expired session token', 401);
        }

        if (!isset($payload['id']) || !isset($payload['expires']) || now()->timestamp > $payload['expires']) {
            throw new AuthException('Session expired, please login again', 401);
        }

        $user = $this->userModel::find($payload['id']);
        if (!$user) {
            throw new AuthException('User not found', 404);
        }

        // 2. Verify OTP
        $this->twoFactorService->verify($user, $code, $deviceId);

        // 3. Finalize Login
        $this->securityService->clearFailedAttempts($user->email);
        
        return $this->finalizeLoginFromData(
             $user,
             $deviceId,
             $deviceName,
             $ipAddress,
             $userAgent
        );
    }

    protected function generateTempToken($user): string
    {
        $payload = [
            'id' => $user->id,
            'expires' => now()->addMinutes(10)->timestamp,
        ];
        
        return Crypt::encryptString(json_encode($payload));
    }

    public function socialRedirect($provider): AuthResult
    {
        $redirect = $this->socialLoginService->redirect($provider);
        return new AuthResult(user: $redirect, message: 'Redirecting');
    }

    public function handleSocialCallback($provider, Request $request): AuthResult
    {
        $result = $this->socialLoginService->handleCallback($provider, $request);
        return new AuthResult(user: $result['user'], message: 'Social login successful');
    }

    public function getDevices($user)
    {
        return $this->deviceService->getActiveSessions($user);
    }

    public function removeDevice($user, string $deviceId): void
    {
        $this->deviceService->invalidateSession($user, $deviceId);
    }
}
