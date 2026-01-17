<?php

namespace Redoy\AuthMaster\Services;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Redoy\AuthMaster\Contracts\DeviceSessionServiceInterface;
use Redoy\AuthMaster\Contracts\SocialLoginServiceInterface;
use Redoy\AuthMaster\Contracts\TokenServiceInterface;
use Redoy\AuthMaster\Exceptions\AuthException;
use Laravel\Socialite\Facades\Socialite;
use Throwable;

class SocialLoginService implements SocialLoginServiceInterface
{
    public function __construct(
        protected TokenServiceInterface $tokenService,
        protected DeviceSessionServiceInterface $deviceService
    ) {
    }

    protected function socialiteAvailable(): bool
    {
        return class_exists('Laravel\Socialite\Facades\Socialite');
    }

    public function redirect(string $provider): \Illuminate\Http\RedirectResponse
    {
        $providers = config('authmaster.social_providers', []);
        if (!isset($providers[$provider]) || !$providers[$provider]['enabled']) {
            throw new AuthException('Provider disabled', 400);
        }

        if (!$this->socialiteAvailable()) {
            throw new AuthException('Socialite not installed', 500);
        }

        try {
            $redirectUrl = Socialite::driver($provider)->stateless()->redirect()->getTargetUrl();
            return redirect($redirectUrl);
        } catch (Throwable $e) {
            Log::error('AuthMaster Social redirect error: ' . $e->getMessage());
            throw new AuthException('Failed to create social redirect', 500);
        }
    }

    /**
     * Handle the callback from a social provider.
     *
     * @param string $provider The social provider name
     * @param Request $request The HTTP request
     * @return array Result with user data and token
     * @throws \Redoy\AuthMaster\Exceptions\AuthException
     */
    public function handleCallback(string $provider, Request $request): array
    {
        $providers = config('authmaster.social_providers', []);
        if (!isset($providers[$provider]) || !$providers[$provider]['enabled']) {
            throw new AuthException('Provider disabled', 400);
        }

        if (!$this->socialiteAvailable()) {
            throw new AuthException('Socialite not installed', 500);
        }

        try {
            $socialUser = Socialite::driver($provider)->stateless()->user();
        } catch (Throwable $e) {
            Log::error('AuthMaster Social callback error: ' . $e->getMessage());
            throw new AuthException('Failed to fetch social user', 400);
        }

        if (empty($socialUser->getEmail())) {
            throw new AuthException('No email returned by provider', 400);
        }

        $userModel = config('auth.providers.users.model');
        $user = $userModel::where('email', $socialUser->getEmail())->first();

        if (!$user) {
            $user = new $userModel();
            $user->name = $socialUser->getName() ?? $socialUser->getNickname() ?? 'No Name';
            $user->email = $socialUser->getEmail();
            $user->password = Hash::make(Str::random(24));
            $user->save();
        }

        $deviceId = hash('sha256', $request->ip() . '|' . $request->userAgent());

        $tokenData = $this->tokenService->createTokenForUser($user, $deviceId);
        $this->deviceService->createOrUpdateSession($user, $deviceId, $request, $tokenData['token_id'] ?? null, $tokenData);

        return ['user' => $user, 'token' => $tokenData];
    }
}
