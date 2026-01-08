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

    protected function otpCacheKey($userId): string
    {
        return "authmaster_email_otp:{$userId}";
    }

    protected function resendCooldownKey($identifier): string
    {
        return "authmaster_resend_cooldown:" . md5($identifier);
    }

    protected function tokenCacheKey(string $token): string
    {
        return "authmaster_email_token:{$token}";
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

    public function sendOtp($user): array
    {
        $delay = $this->checkResendDelay($user->email);
        if ($delay) {
            return ['success' => false, 'message' => "Please wait {$delay} seconds before requesting a new code"];
        }

        $length = config('authmaster.otp.length', 6);
        $ttl = config('authmaster.registration.verification_expires', 3600);

        $code = $this->otpGenerator->generate($length);
        $key = $this->otpCacheKey($user->id);

        Cache::put($key, $code, $ttl);
        $this->setResendDelay($user->email);

        if (config('authmaster.otp.use_queue', true)) {
            SendOtpJob::dispatch($user, $code);
        } else {
            SendOtpJob::dispatchSync($user, $code);
        }

        return ['success' => true, 'message' => 'Verification OTP sent to your email'];
    }

    public function verifyOtp($user, string $code): array
    {
        $key = $this->otpCacheKey($user->id);
        $cached = Cache::get($key);

        if (!$cached) {
            return ['success' => false, 'message' => 'Verification code expired or not found'];
        }

        if (!hash_equals((string) $cached, (string) $code)) {
            return ['success' => false, 'message' => 'Invalid verification code'];
        }

        Cache::forget($key);
        $this->markAsVerified($user);

        return ['success' => true, 'message' => 'Email verified successfully'];
    }

    public function sendLink($user): array
    {
        $delay = $this->checkResendDelay($user->email);
        if ($delay) {
            return ['success' => false, 'message' => "Please wait {$delay} seconds before requesting a new link"];
        }

        $ttl = config('authmaster.registration.verification_expires', 3600);
        $token = Str::random(64);

        $key = $this->tokenCacheKey($token);
        Cache::put($key, $user->id, $ttl);
        $this->setResendDelay($user->email);

        $baseUrl = config('authmaster.registration.verification_url', '/verify-email');
        $verificationUrl = url($baseUrl) . '?token=' . $token;

        if (config('authmaster.otp.use_queue', true)) {
            SendVerificationLinkJob::dispatch($user, $verificationUrl);
        } else {
            SendVerificationLinkJob::dispatchSync($user, $verificationUrl);
        }

        return ['success' => true, 'message' => 'Verification link sent to your email'];
    }

    public function verifyLink(string $token): array
    {
        $key = $this->tokenCacheKey($token);
        $userId = Cache::get($key);

        if (!$userId) {
            return ['success' => false, 'message' => 'Verification link expired or invalid'];
        }

        $user = $this->userModel::find($userId);

        if (!$user) {
            return ['success' => false, 'message' => 'User not found'];
        }

        Cache::forget($key);
        $this->markAsVerified($user);

        return ['success' => true, 'message' => 'Email verified successfully', 'user' => $user];
    }

    public function sendVerification($user): array
    {
        $method = $this->getVerificationMethod();

        if ($method === 'otp') {
            return $this->sendOtp($user);
        }

        if ($method === 'link') {
            return $this->sendLink($user);
        }

        return ['success' => true, 'message' => 'No verification required'];
    }

    protected function pendingRegistrationKey(string $email): string
    {
        return "authmaster_pending_reg:" . md5($email);
    }

    public function storePendingRegistration(array $data): array
    {
        $email = $data['email'];
        $ttl = config('authmaster.registration.verification_expires', 3600);

        // Check previously handled by RegisterRequest validation

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
                SendOtpJob::dispatch($tempUser, $code);
            } else {
                SendOtpJob::dispatchSync($tempUser, $code);
            }

            return ['success' => true, 'message' => 'Verification code sent to your email'];
        }

        if ($method === 'link') {
            $token = Str::random(64);
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
                SendVerificationLinkJob::dispatch($tempUser, $verificationUrl);
            } else {
                SendVerificationLinkJob::dispatchSync($tempUser, $verificationUrl);
            }

            $result = ['success' => true, 'message' => 'Verification link sent to your email'];

            if (!app()->isProduction()) {
                $result['dev_verification_url'] = $verificationUrl;
                $result['dev_token'] = $token;
            }

            return $result;
        }

        return ['success' => false, 'message' => 'Invalid verification method'];
    }

    public function verifyPendingRegistration(string $email, string $code): array
    {
        $key = $this->pendingRegistrationKey($email);
        $pendingData = Cache::get($key);

        if (!$pendingData) {
            return ['success' => false, 'message' => 'No pending registration found or it has expired'];
        }

        if (!hash_equals((string) $pendingData['otp'], (string) $code)) {
            return ['success' => false, 'message' => 'Invalid verification code'];
        }

        // Race condition check: re-verify email hasn't been taken in the meantime
        if ($this->userModel::where('email', $email)->exists()) {
            Cache::forget($key);
            return ['success' => false, 'message' => 'Email already registered'];
        }

        $user = $this->userModel::create([
            'name' => $pendingData['name'],
            'email' => $pendingData['email'],
            'password' => $pendingData['password'],
        ]);

        $this->markAsVerified($user);

        Cache::forget($key);

        return [
            'success' => true,
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
            return ['success' => false, 'message' => 'Verification link expired or invalid'];
        }

        // Race condition check: re-verify email hasn't been taken in the meantime
        if ($this->userModel::where('email', $pendingData['email'])->exists()) {
            Cache::forget($key);
            return ['success' => false, 'message' => 'Email already registered'];
        }

        $user = $this->userModel::create([
            'name' => $pendingData['name'],
            'email' => $pendingData['email'],
            'password' => $pendingData['password'],
        ]);

        $this->markAsVerified($user);

        Cache::forget($key);

        return [
            'success' => true,
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
            return ['success' => false, 'message' => "Please wait {$delay} seconds before requesting a new code"];
        }

        $key = $this->pendingRegistrationKey($email);
        $pendingData = Cache::get($key);

        if (!$pendingData) {
            return ['success' => false, 'message' => 'No pending registration found'];
        }

        $code = $this->otpGenerator->generate(config('authmaster.otp.length', 6));
        $pendingData['otp'] = $code;

        $ttl = config('authmaster.registration.verification_expires', 3600);
        Cache::put($key, $pendingData, $ttl);
        $this->setResendDelay($email);

        $tempUser = (object) ['name' => $pendingData['name'], 'email' => $email];
        if (config('authmaster.otp.use_queue', true)) {
            SendOtpJob::dispatch($tempUser, $code);
        } else {
            SendOtpJob::dispatchSync($tempUser, $code);
        }

        return ['success' => true, 'message' => 'New verification code sent'];
    }

    public function isPendingFlowEnabled(): bool
    {
        $method = $this->getVerificationMethod();
        return ($method === 'otp' || $method === 'link')
            && config('authmaster.registration.verify_before_create', true);
    }
}
