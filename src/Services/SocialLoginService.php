<?php

namespace Redoy\AuthMaster\Services;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;

class SocialLoginService
{
    protected ?\Closure $socialiteFactory = null;

    public function __construct()
    {
        // Socialite may not be available; we will check at runtime
    }

    protected function socialiteAvailable(): bool
    {
        return class_exists('\Laravel\Socialite\Facades\Socialite');
    }

    public function redirect(string $provider): array
    {
        $providers = config('authmaster.social_providers', []);
        if (!isset($providers[$provider]) || !$providers[$provider]['enabled']) {
            return ['success' => false, 'message' => 'Provider disabled'];
        }

        if (!$this->socialiteAvailable()) {
            return ['success' => false, 'message' => 'Socialite not installed'];
        }

        try {
            $redirect = \Laravel\Socialite\Facades\Socialite::driver($provider)->stateless()->redirect()->getTargetUrl();
            return ['success' => true, 'redirect' => redirect($redirect)];
        } catch (\Throwable $e) {
            Log::error('AuthMaster Social redirect error: ' . $e->getMessage());
            return ['success' => false, 'message' => 'Failed to create social redirect'];
        }
    }

    public function handleCallback(string $provider, Request $request): array
    {
        $providers = config('authmaster.social_providers', []);
        if (!isset($providers[$provider]) || !$providers[$provider]['enabled']) {
            return ['success' => false, 'message' => 'Provider disabled'];
        }

        if (!$this->socialiteAvailable()) {
            return ['success' => false, 'message' => 'Socialite not installed'];
        }

        try {
            $socialUser = \Laravel\Socialite\Facades\Socialite::driver($provider)->stateless()->user();
        } catch (\Throwable $e) {
            Log::error('AuthMaster Social callback error: ' . $e->getMessage());
            return ['success' => false, 'message' => 'Failed to fetch social user'];
        }

        if (empty($socialUser->getEmail())) {
            return ['success' => false, 'message' => 'No email returned by provider'];
        }

        $userModel = config('auth.providers.users.model');
        $user = $userModel::where('email', $socialUser->getEmail())->first();

        if (!$user) {
            $user = new $userModel();
            $user->name = $socialUser->getName() ?? $socialUser->getNickname() ?? 'No Name';
            $user->email = $socialUser->getEmail();
            // random password
            $user->password = Hash::make(Str::random(24));
            $user->save();
        }

        // create token
        $deviceId = hash('sha256', $request->ip() . '|' . $request->userAgent());
        $tokenService = app(TokenService::class);
        $deviceService = app(DeviceSessionService::class);

        $tokenData = $tokenService->createTokenForUser($user, $deviceId);
        $deviceService->createOrUpdateSession($user, $deviceId, $request, $tokenData['token_id'] ?? null, $tokenData);

        return ['success' => true, 'data' => ['user' => $user, 'token' => $tokenData]];
    }
}
