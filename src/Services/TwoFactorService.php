<?php

namespace Redoy\AuthMaster\Services;

use Illuminate\Support\Facades\Cache;
use Redoy\AuthMaster\Contracts\OtpGeneratorInterface;
use Redoy\AuthMaster\Contracts\TwoFactorServiceInterface;
use Redoy\AuthMaster\Jobs\SendOtpJob;
use Redoy\AuthMaster\Exceptions\AuthException;

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

    protected function resendCooldownKey($userId): string
    {
        return "authmaster_2fa_resend_cooldown:{$userId}";
    }

    protected function checkResendDelay($userId): ?int
    {
        $key = $this->resendCooldownKey($userId);
        $expiresAt = Cache::get($key);

        if ($expiresAt && now()->timestamp < $expiresAt) {
            return $expiresAt - now()->timestamp;
        }

        return null;
    }

    protected function setResendDelay($userId): void
    {
        $delay = config('authmaster.otp.resend_delay_seconds', 60);
        $key = $this->resendCooldownKey($userId);
        Cache::put($key, now()->timestamp + $delay, $delay);
    }

    public function generateAndSend($user, ?string $deviceId = null): void
    {
        $delay = $this->checkResendDelay($user->id);
        if ($delay) {
            throw new AuthException("Please wait {$delay} seconds before requesting a new OTP", 429);
        }

        $length = config('authmaster.otp.length', 6);
        $ttl = config('authmaster.otp.ttl', 300);

        $device = $deviceId ?? 'global';
        $code = $this->otpGenerator->generate($length);

        $key = $this->cacheKey($user->id, $device);
        Cache::put($key, $code, $ttl);
        $this->setResendDelay($user->id);

        if (config('authmaster.otp.use_queue', true)) {
            SendOtpJob::dispatch($user, $code);
        } else {
            (new SendOtpJob($user, $code))->handle();
        }
    }

    /**
     * Verify a 2FA OTP code.
     *
     * @param mixed $user The user instance
     * @param string $code The OTP code to verify
     * @param string|null $deviceId Optional device identifier
     * @return void
     * @throws \Redoy\AuthMaster\Exceptions\AuthException
     */
    public function verify($user, string $code, ?string $deviceId = null): void
    {
        $device = $deviceId ?? 'global';
        $key = $this->cacheKey($user->id, $device);
        $cached = Cache::get($key);

        if (!$cached) {
            throw new AuthException('Code expired or not found', 422);
        }

        if (!hash_equals((string) $cached, (string) $code)) {
            throw new AuthException('Invalid code', 422);
        }

        Cache::forget($key);
    }

    public function isTwoFactorRequiredFor($user): bool
    {
        if (!config('authmaster.enable_2fa', true)) {
            return false;
        }

        if (config('authmaster.otp.force_for_all', false)) {
            return true;
        }

        if (isset($user->two_factor_enabled)) {
            return (bool) $user->two_factor_enabled;
        }

        return false;
    }
}
