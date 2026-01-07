<?php

namespace Redoy\AuthMaster\Services;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Mail;
use Redoy\AuthMaster\Contracts\OtpGeneratorInterface;
use Redoy\AuthMaster\Contracts\TwoFactorServiceInterface;
use Redoy\AuthMaster\Mail\SendOtpMail;

class TwoFactorService implements TwoFactorServiceInterface
{
    public function __construct(
        protected OtpGeneratorInterface $otpGenerator
    ) {
    }

    protected function cacheKey($userId, string $deviceId = 'global'): string
    {
        return "authmaster_otp:{$userId}:{$deviceId}";
    }

    public function generateAndSend($user, ?string $deviceId = null): array
    {
        $length = config('authmaster.otp.length', 6);
        $ttl = config('authmaster.otp.ttl', 300);

        $device = $deviceId ?? 'global';
        $code = $this->otpGenerator->generate($length);

        $key = $this->cacheKey($user->id, $device);
        Cache::put($key, $code, $ttl);

        try {
            Mail::to($user->email)->send(new SendOtpMail($user, $code));
            return ['success' => true];
        } catch (\Throwable $e) {
            return ['success' => false, 'message' => 'Failed to send OTP'];
        }
    }

    public function verify($user, string $code, ?string $deviceId = null): array
    {
        $device = $deviceId ?? 'global';
        $key = $this->cacheKey($user->id, $device);
        $cached = Cache::get($key);

        if (!$cached) {
            return ['success' => false, 'message' => 'Code expired or not found'];
        }

        if (!hash_equals((string) $cached, (string) $code)) {
            return ['success' => false, 'message' => 'Invalid code'];
        }

        Cache::forget($key);
        return ['success' => true];
    }

    public function isTwoFactorRequiredFor($user): bool
    {
        if (!config('authmaster.enable_2fa', true)) {
            return false;
        }

        // If forced globally
        if (config('authmaster.otp.force_for_all', false)) {
            return true;
        }

        // If user has a flag
        if (isset($user->two_factor_enabled)) {
            return (bool) $user->two_factor_enabled;
        }

        return false;
    }
}
