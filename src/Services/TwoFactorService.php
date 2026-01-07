<?php

namespace Redoy\AuthMaster\Services;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Str;
use Redoy\AuthMaster\Mail\SendOtpMail;

class TwoFactorService
{
    protected function cacheKey($userId, string $deviceId = 'global')
    {
        return "authmaster_otp:{$userId}:{$deviceId}";
    }

    protected function generateNumericCode(int $length = 6): string
    {
        $min = (int) str_repeat('0', $length);
        $max = (int) str_repeat('9', $length);
        $code = '';
        for ($i = 0; $i < $length; $i++) {
            $code .= (string) random_int(0, 9);
        }
        return $code;
    }

    public function generateAndSend($user, ?string $deviceId = null): array
    {
        $length = config('authmaster.otp.length', 6);
        $ttl = config('authmaster.otp.ttl', 300);

        $device = $deviceId ?? 'global';
        $code = $this->generateNumericCode($length);

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
