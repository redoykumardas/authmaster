<?php

namespace Redoy\AuthMaster\Services;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
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
use Redoy\AuthMaster\Exceptions\InvalidCredentialsException;
use Redoy\AuthMaster\Exceptions\TooManyAttemptsException;
use Redoy\AuthMaster\Exceptions\TwoFactorRequiredException;

class AuthManager implements AuthManagerInterface
{
    public function __construct(
        protected ValidationManagerInterface $validator,
        protected TokenServiceInterface $tokenService,
        protected DeviceSessionServiceInterface $deviceService,
        protected PasswordServiceInterface $passwordService,
        protected TwoFactorServiceInterface $twoFactorService,
        protected SecurityServiceInterface $securityService,
        protected SocialLoginServiceInterface $socialLoginService
    ) {
    }

    public function extractDeviceId(Request $request): string
    {
        if ($request->header('device_id')) {
            return (string) $request->header('device_id');
        }

        return hash('sha256', $request->ip() . '|' . $request->userAgent());
    }

    public function login(Request $request): AuthResult
    {
        $credentials = $request->only('email', 'password');
        $deviceId = $this->extractDeviceId($request);

        // Security checks: rate limit, lockout
        if (!$this->securityService->allowLoginAttempt($credentials['email'] ?? null, $request->ip())) {
            throw new TooManyAttemptsException();
        }

        if (!Auth::attempt($credentials)) {
            $this->securityService->recordFailedAttempt($credentials['email'] ?? null, $request->ip());
            throw new InvalidCredentialsException();
        }

        $user = Auth::user();

        // Check 2FA requirement
        if (config('authmaster.enable_2fa') && $this->twoFactorService->isTwoFactorRequiredFor($user)) {
            // send OTP and require verification flow in caller
            $this->twoFactorService->generateAndSend($user, $deviceId);
            throw new TwoFactorRequiredException();
        }

        $this->securityService->clearFailedAttempts($user->email);

        return $this->finalizeLogin($user, $request, $deviceId, $request->input('device_name'));
    }

    public function loginWithData(LoginData $data): AuthResult
    {
        if (!$this->securityService->allowLoginAttempt($data->email, $data->ipAddress)) {
            throw new TooManyAttemptsException();
        }

        if (!Auth::attempt(['email' => $data->email, 'password' => $data->password])) {
            $this->securityService->recordFailedAttempt($data->email, $data->ipAddress);
            throw new InvalidCredentialsException();
        }

        $user = Auth::user();

        if (config('authmaster.enable_2fa') && $this->twoFactorService->isTwoFactorRequiredFor($user)) {
            $this->twoFactorService->generateAndSend($user, $data->deviceId);
            throw new TwoFactorRequiredException();
        }

        $this->securityService->clearFailedAttempts($user->email);

        return $this->finalizeLoginFromData($user, $data->deviceId, $data->deviceName);
    }

    /**
     * Finalize the login process: create token, store session, and enforce limits.
     */
    public function finalizeLogin($user, Request $request, string $deviceId, string $deviceName = null): AuthResult
    {
        $tokenData = $this->tokenService->createTokenForUser($user, $deviceId);

        $this->deviceService->createOrUpdateSession($user, $deviceId, $request, $tokenData['token_id'] ?? null, $tokenData, $deviceName);

        $this->deviceService->enforceDeviceLimit($user);

        return new AuthResult(
            user: $user,
            token: $tokenData,
            message: 'Logged in'
        );
    }

    /**
     * Finalize login using device data directly (for DTO-based flows).
     */
    public function finalizeLoginFromData($user, string $deviceId, ?string $deviceName = null): AuthResult
    {
        $tokenData = $this->tokenService->createTokenForUser($user, $deviceId);

        // Create a minimal request-like object for session storage
        $this->deviceService->createOrUpdateSessionFromData($user, $deviceId, $tokenData['token_id'] ?? null, $tokenData, $deviceName);

        $this->deviceService->enforceDeviceLimit($user);

        return new AuthResult(
            user: $user,
            token: $tokenData,
            message: 'Logged in'
        );
    }

    public function register(Request $request): AuthResult
    {
        $data = $request->only(['name', 'email', 'password']);
        $deviceId = $this->extractDeviceId($request);
        $deviceName = $request->input('device_name');

        $userModel = config('auth.providers.users.model');
        $user = new $userModel();
        $user->name = $data['name'];
        $user->email = $data['email'];
        $user->password = Hash::make($data['password']);
        $user->save();

        // Auto-login after registration
        Auth::login($user);

        return $this->finalizeLogin($user, $request, $deviceId, $deviceName);
    }

    public function logoutCurrentDevice(Request $request): void
    {
        $deviceId = $this->extractDeviceId($request);
        $user = $request->user();
        if ($user) {
            $this->deviceService->invalidateSession($user, $deviceId);
        }
    }

    public function logoutAllDevices(Request $request): void
    {
        $user = $request->user();
        if ($user) {
            $this->deviceService->invalidateAllSessions($user);
        }
    }

    public function updateProfile($user, array $data): AuthResult
    {
        $user->fill($data);
        $user->save();
        return new AuthResult(user: $user, message: 'Profile updated');
    }

    public function changePassword($user, array $payload): AuthResult
    {
        if (!Hash::check($payload['current_password'], $user->password)) {
            throw new \Redoy\AuthMaster\Exceptions\AuthException('Current password does not match', 422);
        }
        $user->password = Hash::make($payload['password']);
        $user->save();
        return new AuthResult(message: 'Password changed');
    }

    public function sendPasswordResetLink(array $payload): AuthResult
    {
        $result = $this->passwordService->sendResetLink($payload['email']);
        if (!$result['success']) {
            throw new \Redoy\AuthMaster\Exceptions\AuthException($result['message'] ?? 'Failed to send reset email', 422);
        }
        return new AuthResult(message: 'Reset email sent');
    }

    public function resetPassword(array $payload): AuthResult
    {
        $result = $this->passwordService->resetPassword($payload);
        if (!$result['success']) {
            throw new \Redoy\AuthMaster\Exceptions\AuthException($result['message'] ?? 'Failed to reset password', 422);
        }
        return new AuthResult(message: 'Password reset');
    }

    public function resetPasswordWithData(PasswordResetData $data): AuthResult
    {
        $result = $this->passwordService->resetPassword([
            'email' => $data->email,
            'password' => $data->password,
            'token' => $data->token,
        ]);

        if (!$result['success']) {
            throw new \Redoy\AuthMaster\Exceptions\AuthException($result['message'] ?? 'Failed to reset password', 422);
        }

        return new AuthResult(message: 'Password reset');
    }

    public function sendTwoFactor($user): AuthResult
    {
        $result = $this->twoFactorService->generateAndSend($user, null);
        if (!$result['success']) {
            throw new \Redoy\AuthMaster\Exceptions\AuthException($result['message'] ?? 'Failed to send OTP', 422);
        }
        return new AuthResult(message: 'OTP sent');
    }

    public function verifyTwoFactor($user, $code): AuthResult
    {
        $result = $this->twoFactorService->verify($user, $code);
        if (!$result['success']) {
            throw new \Redoy\AuthMaster\Exceptions\AuthException($result['message'] ?? 'Invalid code', 422);
        }
        return new AuthResult(message: 'OTP verified');
    }

    public function socialRedirect($provider): AuthResult
    {
        $result = $this->socialLoginService->redirect($provider);
        if (isset($result['redirect'])) {
            // This is a special case where we might need to return a redirect response
            // For now, let's keep it in AuthResult? 
            // Actually socialRedirect is different. Let's return AuthResult with a special property maybe?
            // Or just return the redirect from here if we want thin controllers.
            // But AuthResult is Responsable.
            return new AuthResult(user: $result['redirect'], message: 'Redirecting');
        }
        throw new \Redoy\AuthMaster\Exceptions\AuthException($result['message'] ?? 'Provider not available', 400);
    }

    public function handleSocialCallback($provider, Request $request): AuthResult
    {
        $result = $this->socialLoginService->handleCallback($provider, $request);
        if (!$result['success']) {
            throw new \Redoy\AuthMaster\Exceptions\AuthException($result['message'] ?? 'Social login failed', 400);
        }
        return new AuthResult(user: $result['data'], message: 'Social login successful');
    }
}
