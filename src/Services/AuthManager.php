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

    public function login(Request $request): array
    {
        $credentials = $request->only('email', 'password');
        $deviceId = $this->extractDeviceId($request);

        // Security checks: rate limit, lockout
        if (!$this->securityService->allowLoginAttempt($credentials['email'] ?? null, $request->ip())) {
            return ['success' => false, 'message' => 'Too many login attempts.'];
        }

        if (!Auth::attempt($credentials)) {
            $this->securityService->recordFailedAttempt($credentials['email'] ?? null, $request->ip());
            return ['success' => false, 'message' => 'Invalid credentials'];
        }

        $user = Auth::user();

        // Check 2FA requirement
        if (config('authmaster.enable_2fa') && $this->twoFactorService->isTwoFactorRequiredFor($user)) {
            // send OTP and require verification flow in caller
            $this->twoFactorService->generateAndSend($user, $deviceId);
            return ['success' => false, 'message' => '2fa_required'];
        }

        $this->securityService->clearFailedAttempts($user->email);

        return $this->finalizeLogin($user, $request, $deviceId, $request->input('device_name'));
    }

    public function loginWithData(LoginData $data): array
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
    public function finalizeLogin($user, Request $request, string $deviceId, string $deviceName = null): array
    {
        $tokenData = $this->tokenService->createTokenForUser($user, $deviceId);

        $this->deviceService->createOrUpdateSession($user, $deviceId, $request, $tokenData['token_id'] ?? null, $tokenData, $deviceName);

        $this->deviceService->enforceDeviceLimit($user);

        return ['success' => true, 'data' => ['user' => $user, 'token' => $tokenData]];
    }

    /**
     * Finalize login using device data directly (for DTO-based flows).
     */
    public function finalizeLoginFromData($user, string $deviceId, ?string $deviceName = null): array
    {
        $tokenData = $this->tokenService->createTokenForUser($user, $deviceId);

        // Create a minimal request-like object for session storage
        $this->deviceService->createOrUpdateSessionFromData($user, $deviceId, $tokenData['token_id'] ?? null, $tokenData, $deviceName);

        $this->deviceService->enforceDeviceLimit($user);

        return ['user' => $user, 'token' => $tokenData];
    }

    public function register(Request $request): array
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

    public function updateProfile($user, array $data)
    {
        $user->fill($data);
        $user->save();
        return $user;
    }

    public function changePassword($user, array $payload): array
    {
        if (!Hash::check($payload['current_password'], $user->password)) {
            return ['success' => false, 'message' => 'Current password does not match'];
        }
        $user->password = Hash::make($payload['password']);
        $user->save();
        return ['success' => true];
    }

    public function sendPasswordResetLink(array $payload): array
    {
        return $this->passwordService->sendResetLink($payload['email']);
    }

    public function resetPassword(array $payload): array
    {
        return $this->passwordService->resetPassword($payload);
    }

    public function resetPasswordWithData(PasswordResetData $data): array
    {
        return $this->passwordService->resetPassword([
            'email' => $data->email,
            'password' => $data->password,
            'token' => $data->token,
        ]);
    }

    public function sendTwoFactor($user): array
    {
        return $this->twoFactorService->generateAndSend($user, null);
    }

    public function verifyTwoFactor($user, $code): array
    {
        return $this->twoFactorService->verify($user, $code);
    }

    public function socialRedirect($provider): array
    {
        return $this->socialLoginService->redirect($provider);
    }

    public function handleSocialCallback($provider, Request $request): array
    {
        return $this->socialLoginService->handleCallback($provider, $request);
    }
}
