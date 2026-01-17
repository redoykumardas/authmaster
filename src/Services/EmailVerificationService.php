<?php

namespace Redoy\AuthMaster\Services;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Str;
use Redoy\AuthMaster\Contracts\EmailVerificationServiceInterface;
use Redoy\AuthMaster\Contracts\OtpGeneratorInterface;
use Redoy\AuthMaster\Jobs\SendOtpJob;
use Redoy\AuthMaster\Jobs\SendVerificationLinkJob;

class EmailVerificationService implements EmailVerificationServiceInterface
{
    protected $userModel;

    public function __construct(
        protected OtpGeneratorInterface $otpGenerator
    ) {
        $this->userModel = config('auth.providers.users.model');
    }

    public function getVerificationMethod(): string
    {
        return config('authmaster.registration.email_verification', 'none');
    }

    public function isVerificationRequired(): bool
    {
        return $this->getVerificationMethod() !== 'none';
    }

    public function isVerified($user): bool
    {
        return !is_null($user->email_verified_at);
    }

    public function markAsVerified($user): void
    {
        $user->forceFill([
            'email_verified_at' => now(),
        ])->save();
    }

    protected function resendCooldownKey($identifier): string
    {
        return "authmaster_resend_cooldown:" . md5($identifier);
    }

    protected function checkResendDelay(string $identifier): ?int
    {
        $key = $this->resendCooldownKey($identifier);
        $expiresAt = Cache::get($key);

        if ($expiresAt && now()->timestamp < $expiresAt) {
            return $expiresAt - now()->timestamp;
        }

        return null;
    }

    protected function setResendDelay(string $identifier): void
    {
        $delay = config('authmaster.otp.resend_delay_seconds', 60);
        $key = $this->resendCooldownKey($identifier);
        Cache::put($key, now()->timestamp + $delay, $delay);
    }


    protected function pendingRegistrationKey(string $email): string
    {
        return "authmaster_pending_reg:" . md5($email);
    }

    public function storePendingRegistration(array $data): array
    {
        $email = $data['email'];

        if ($this->hasPendingRegistration($email)) {
            throw new \Redoy\AuthMaster\Exceptions\AuthException('Your email is in registration process, verify otp or wait some time and try again.', 429);
        }

        $ttl = config('authmaster.registration.verification_expires', 3600);

        $method = $this->getVerificationMethod();
        $pendingData = [
            'name' => $data['name'],
            'email' => $data['email'],
            'password' => $data['password'],
            'created_at' => now()->toISOString(),
            'method' => $method,
            'device_id' => $data['device_id'] ?? null,
            'device_name' => $data['device_name'] ?? null,
            'ip_address' => $data['ip_address'] ?? null,
            'user_agent' => $data['user_agent'] ?? null,
        ];

        if ($method === 'otp') {
            $code = $this->otpGenerator->generate(config('authmaster.otp.length', 6));
            $pendingData['otp'] = $code;

            $key = $this->pendingRegistrationKey($email);
            Cache::put($key, $pendingData, $ttl);
            $this->setResendDelay($email);

            $tempUser = (object) ['name' => $data['name'], 'email' => $email];
            if (config('authmaster.otp.use_queue', true)) {
                \Redoy\AuthMaster\Jobs\SendOtpJob::dispatch($tempUser, $code);
            } else {
                \Redoy\AuthMaster\Jobs\SendOtpJob::dispatchSync($tempUser, $code);
            }

            return ['message' => 'Verification code sent to your email'];
        }

        if ($method === 'link') {
            $token = \Illuminate\Support\Str::random(64);
            $devToken = config('authmaster.registration.dev_token');
            if ($devToken && !app()->isProduction()) {
                $token = $devToken;
            }

            $tokenKey = "authmaster_pending_token:{$token}";
            Cache::put($tokenKey, $pendingData, $ttl);
            $this->setResendDelay($email);

            $baseUrl = config('authmaster.registration.verification_url', '/verify-email');
            $verificationUrl = url($baseUrl) . '?token=' . $token;

            $tempUser = (object) ['name' => $data['name'], 'email' => $email];
            if (config('authmaster.otp.use_queue', true)) {
                \Redoy\AuthMaster\Jobs\SendVerificationLinkJob::dispatch($tempUser, $verificationUrl);
            } else {
                \Redoy\AuthMaster\Jobs\SendVerificationLinkJob::dispatchSync($tempUser, $verificationUrl);
            }

            $result = ['message' => 'Verification link sent to your email'];

            if (!app()->isProduction()) {
                $result['dev_verification_url'] = $verificationUrl;
                $result['dev_token'] = $token;
            }

            return $result;
        }

        throw new \Redoy\AuthMaster\Exceptions\AuthException('Invalid verification method', 400);
    }

    public function verifyPendingRegistration(string $email, string $code): array
    {
        $key = $this->pendingRegistrationKey($email);
        $pendingData = Cache::get($key);

        if (!$pendingData) {
            throw new \Redoy\AuthMaster\Exceptions\VerificationFailedException('No pending registration found or it has expired');
        }

        if (!hash_equals((string) $pendingData['otp'], (string) $code)) {
            throw new \Redoy\AuthMaster\Exceptions\VerificationFailedException('Invalid verification code');
        }

        // Race condition check: re-verify email hasn't been taken in the meantime
        if ($this->userModel::where('email', $email)->exists()) {
            Cache::forget($key);
            throw new \Redoy\AuthMaster\Exceptions\VerificationFailedException('Email already registered');
        }

        $user = $this->userModel::create([
            'name' => $pendingData['name'],
            'email' => $pendingData['email'],
            'password' => $pendingData['password'],
        ]);

        $this->markAsVerified($user);

        Cache::forget($key);

        return [
            'message' => 'Email verified and account created successfully',
            'user' => $user,
            'device_id' => $pendingData['device_id'] ?? null,
            'device_name' => $pendingData['device_name'] ?? null,
            'ip_address' => $pendingData['ip_address'] ?? null,
            'user_agent' => $pendingData['user_agent'] ?? null,
        ];
    }

    public function verifyPendingLink(string $token): array
    {
        $key = "authmaster_pending_token:{$token}";
        $pendingData = Cache::get($key);

        if (!$pendingData) {
            throw new \Redoy\AuthMaster\Exceptions\VerificationFailedException('Verification link expired or invalid');
        }

        // Race condition check: re-verify email hasn't been taken in the meantime
        if ($this->userModel::where('email', $pendingData['email'])->exists()) {
            Cache::forget($key);
            throw new \Redoy\AuthMaster\Exceptions\VerificationFailedException('Email already registered');
        }

        $user = $this->userModel::create([
            'name' => $pendingData['name'],
            'email' => $pendingData['email'],
            'password' => $pendingData['password'],
        ]);

        $this->markAsVerified($user);

        Cache::forget($key);

        return [
            'message' => 'Email verified and account created successfully',
            'user' => $user,
            'device_id' => $pendingData['device_id'] ?? null,
            'device_name' => $pendingData['device_name'] ?? null,
            'ip_address' => $pendingData['ip_address'] ?? null,
            'user_agent' => $pendingData['user_agent'] ?? null,
        ];
    }

    public function resendPendingOtp(string $email): array
    {
        $delay = $this->checkResendDelay($email);
        if ($delay) {
            throw new \Redoy\AuthMaster\Exceptions\AuthException("Please wait {$delay} seconds before requesting a new code", 429);
        }

        $key = $this->pendingRegistrationKey($email);
        $pendingData = Cache::get($key);

        if (!$pendingData) {
            throw new \Redoy\AuthMaster\Exceptions\AuthException('No pending registration found', 404);
        }

        $code = $this->otpGenerator->generate(config('authmaster.otp.length', 6));
        $pendingData['otp'] = $code;

        $ttl = config('authmaster.registration.verification_expires', 3600);
        Cache::put($key, $pendingData, $ttl);
        $this->setResendDelay($email);

        $tempUser = (object) ['name' => $pendingData['name'], 'email' => $email];
        if (config('authmaster.otp.use_queue', true)) {
            \Redoy\AuthMaster\Jobs\SendOtpJob::dispatch($tempUser, $code);
        } else {
            \Redoy\AuthMaster\Jobs\SendOtpJob::dispatchSync($tempUser, $code);
        }

        return ['message' => 'New verification code sent'];
    }

    public function hasPendingRegistration(string $email): bool
    {
        $key = $this->pendingRegistrationKey($email);
        return Cache::has($key);
    }
}
