<?php

namespace Redoy\AuthMaster\Services;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use Redoy\AuthMaster\Models\DeviceSession;

class AuthManager
{
    protected ValidationManager $validator;
    protected TokenService $tokenService;
    protected DeviceSessionService $deviceService;
    protected PasswordService $passwordService;
    protected TwoFactorService $twoFactorService;
    protected SecurityService $securityService;

    public function __construct(
        ValidationManager $validator,
        TokenService $tokenService,
        DeviceSessionService $deviceService,
        PasswordService $passwordService,
        TwoFactorService $twoFactorService,
        SecurityService $securityService
    ) {
        $this->validator = $validator;
        $this->tokenService = $tokenService;
        $this->deviceService = $deviceService;
        $this->passwordService = $passwordService;
        $this->twoFactorService = $twoFactorService;
        $this->securityService = $securityService;
    }

    protected function extractDeviceId(Request $request): string
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

        // create token
        $tokenData = $this->tokenService->createTokenForUser($user, $deviceId);

        // store device session
        $session = $this->deviceService->createOrUpdateSession($user, $deviceId, $request, $tokenData['token_id'] ?? null, $tokenData);

        // enforce max devices
        $this->deviceService->enforceDeviceLimit($user);

        $this->securityService->clearFailedAttempts($user->email);

        return ['success' => true, 'data' => array_merge(['user' => $user], ['token' => $tokenData])];
    }

    public function register(Request $request): array
    {
        $data = $request->only(['name', 'email', 'password']);
        $deviceId = $this->extractDeviceId($request);

        $userModel = config('auth.providers.users.model');
        $user = new $userModel();
        $user->name = $data['name'];
        $user->email = $data['email'];
        $user->password = Hash::make($data['password']);
        $user->save();

        // Auto-login after registration
        Auth::login($user);

        $tokenData = $this->tokenService->createTokenForUser($user, $deviceId);
        $this->deviceService->createOrUpdateSession($user, $deviceId, $request, $tokenData['token_id'] ?? null, $tokenData);
        $this->deviceService->enforceDeviceLimit($user);

        return ['success' => true, 'data' => array_merge(['user' => $user], ['token' => $tokenData])];
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
        return (new SocialLoginService())->redirect($provider);
    }

    public function handleSocialCallback($provider, Request $request): array
    {
        return (new SocialLoginService())->handleCallback($provider, $request);
    }
}
