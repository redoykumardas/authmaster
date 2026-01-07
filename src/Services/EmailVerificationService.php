<?php

namespace Redoy\AuthMaster\Services;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Str;
use Redoy\AuthMaster\Contracts\EmailVerificationServiceInterface;
use Redoy\AuthMaster\Contracts\OtpGeneratorInterface;
use Redoy\AuthMaster\Mail\SendOtpMail;
use Redoy\AuthMaster\Mail\VerificationLinkMail;

class EmailVerificationService implements EmailVerificationServiceInterface
{
    public function __construct(
        protected OtpGeneratorInterface $otpGenerator
    ) {
    }

    /**
     * Get the verification method from config
     */
    public function getVerificationMethod(): string
    {
        return config('authmaster.registration.email_verification', 'none');
    }

    /**
     * Check if email verification is required
     */
    public function isVerificationRequired(): bool
    {
        return $this->getVerificationMethod() !== 'none';
    }

    /**
     * Check if user email is verified
     */
    public function isVerified($user): bool
    {
        return !is_null($user->email_verified_at);
    }

    /**
     * Mark user as verified
     */
    public function markAsVerified($user): void
    {
        $user->email_verified_at = now();
        $user->save();
    }

    /**
     * Get cache key for OTP
     */
    protected function otpCacheKey($userId): string
    {
        return "authmaster_email_otp:{$userId}";
    }

    /**
     * Get cache key for verification token
     */
    protected function tokenCacheKey(string $token): string
    {
        return "authmaster_email_token:{$token}";
    }

    /**
     * Send OTP to user email
     */
    public function sendOtp($user): array
    {
        $length = config('authmaster.otp.length', 6);
        $ttl = config('authmaster.registration.verification_expires', 3600);

        $code = $this->otpGenerator->generate($length);
        $key = $this->otpCacheKey($user->id);

        Cache::put($key, $code, $ttl);

        try {
            Mail::to($user->email)->send(new SendOtpMail($user, $code));
            return ['success' => true, 'message' => 'Verification OTP sent to your email'];
        } catch (\Throwable $e) {
            return ['success' => false, 'message' => 'Failed to send verification OTP'];
        }
    }

    /**
     * Verify OTP code
     */
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

    /**
     * Send verification link to user email
     */
    public function sendLink($user): array
    {
        $ttl = config('authmaster.registration.verification_expires', 3600);
        $token = Str::random(64);

        $key = $this->tokenCacheKey($token);
        Cache::put($key, $user->id, $ttl);

        $baseUrl = config('authmaster.registration.verification_url', '/verify-email');
        $verificationUrl = url($baseUrl) . '?token=' . $token;

        try {
            Mail::to($user->email)->send(new VerificationLinkMail($user, $verificationUrl));
            return ['success' => true, 'message' => 'Verification link sent to your email'];
        } catch (\Throwable $e) {
            return ['success' => false, 'message' => 'Failed to send verification link'];
        }
    }

    /**
     * Verify link token
     */
    public function verifyLink(string $token): array
    {
        $key = $this->tokenCacheKey($token);
        $userId = Cache::get($key);

        if (!$userId) {
            return ['success' => false, 'message' => 'Verification link expired or invalid'];
        }

        $userModel = config('auth.providers.users.model');
        $user = $userModel::find($userId);

        if (!$user) {
            return ['success' => false, 'message' => 'User not found'];
        }

        Cache::forget($key);
        $this->markAsVerified($user);

        return ['success' => true, 'message' => 'Email verified successfully', 'user' => $user];
    }

    /**
     * Send verification based on configured method
     */
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

    // =========================================================================
    // PENDING REGISTRATION FLOW
    // Stores registration data temporarily until email is verified
    // =========================================================================

    /**
     * Get cache key for pending registration
     */
    protected function pendingRegistrationKey(string $email): string
    {
        return "authmaster_pending_reg:" . md5($email);
    }

    /**
     * Store pending registration data (before email verification)
     */
    public function storePendingRegistration(array $data): array
    {
        $email = $data['email'];
        $ttl = config('authmaster.registration.verification_expires', 3600);

        // Check if email already exists in actual users
        $userModel = config('auth.providers.users.model');
        if ($userModel::where('email', $email)->exists()) {
            return ['success' => false, 'message' => 'Email already registered'];
        }

        $method = $this->getVerificationMethod();
        $pendingData = [
            'name' => $data['name'],
            'email' => $data['email'],
            'password' => $data['password'],
            'created_at' => now()->toISOString(),
            'method' => $method,
            'device_id' => $data['device_id'] ?? null,
            'device_name' => $data['device_name'] ?? null,
        ];

        // ---------------------------------------------------------------------
        // OTP FLOW
        // ---------------------------------------------------------------------
        if ($method === 'otp') {
            $code = $this->otpGenerator->generate(config('authmaster.otp.length', 6));
            $pendingData['otp'] = $code;

            $key = $this->pendingRegistrationKey($email);
            Cache::put($key, $pendingData, $ttl);

            try {
                $tempUser = (object) ['name' => $data['name'], 'email' => $email];
                Mail::to($email)->send(new SendOtpMail($tempUser, $code));
                return ['success' => true, 'message' => 'Verification code sent to your email'];
            } catch (\Throwable $e) {
                return ['success' => false, 'message' => 'Failed to send verification email'];
            }
        }

        // ---------------------------------------------------------------------
        // LINK FLOW
        // ---------------------------------------------------------------------
        if ($method === 'link') {
            $token = Str::random(64);

            // Use dev token in non-production
            $devToken = config('authmaster.registration.dev_token');
            if ($devToken && !app()->isProduction()) {
                $token = $devToken;
            }

            $tokenKey = "authmaster_pending_token:{$token}";

            // Store data keyed by token for link verification
            Cache::put($tokenKey, $pendingData, $ttl);

            // Also store a mapping directly if needed, but for link verif we rely on token.
            // We might want to store email->token mapping if we implement resend logic easily.
            // But let's keep it simple: Link = Token Key.

            $baseUrl = config('authmaster.registration.verification_url', '/verify-email');
            $verificationUrl = url($baseUrl) . '?token=' . $token;

            try {
                $tempUser = (object) ['name' => $data['name'], 'email' => $email];
                Mail::to($email)->send(new VerificationLinkMail($tempUser, $verificationUrl));

                $result = ['success' => true, 'message' => 'Verification link sent to your email'];

                // Return URL in dev environment for convenience
                if (!app()->isProduction()) {
                    $result['dev_verification_url'] = $verificationUrl;
                    $result['dev_token'] = $token;
                }

                return $result;
            } catch (\Throwable $e) {
                return ['success' => false, 'message' => 'Failed to send verification link'];
            }
        }

        return ['success' => false, 'message' => 'Invalid verification method'];
    }

    /**
     * Verify OTP and complete pending registration
     */
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

        // Check again if email was taken while pending
        $userModel = config('auth.providers.users.model');
        if ($userModel::where('email', $email)->exists()) {
            Cache::forget($key);
            return ['success' => false, 'message' => 'Email already registered'];
        }

        // Create actual user
        $user = new $userModel();
        $user->name = $pendingData['name'];
        $user->email = $pendingData['email'];
        $user->password = $pendingData['password'];
        $user->email_verified_at = now();
        $user->save();

        // Clean up pending data
        Cache::forget($key);

        return [
            'success' => true,
            'message' => 'Email verified and account created successfully',
            'user' => $user,
            'device_id' => $pendingData['device_id'] ?? null,
            'device_name' => $pendingData['device_name'] ?? null,
        ];
    }

    /**
     * Verify pending registration via link token
     */
    public function verifyPendingLink(string $token): array
    {
        $key = "authmaster_pending_token:{$token}";
        $pendingData = Cache::get($key);

        if (!$pendingData) {
            return ['success' => false, 'message' => 'Verification link expired or invalid'];
        }

        // Check if email already registered (race condition check)
        $userModel = config('auth.providers.users.model');
        if ($userModel::where('email', $pendingData['email'])->exists()) {
            Cache::forget($key);
            return ['success' => false, 'message' => 'Email already registered'];
        }

        // Create actual user
        $user = new $userModel();
        $user->name = $pendingData['name'];
        $user->email = $pendingData['email'];
        $user->password = $pendingData['password'];
        $user->email_verified_at = now();
        $user->save();

        // Clean up
        Cache::forget($key);

        return [
            'success' => true,
            'message' => 'Email verified and account created successfully',
            'user' => $user,
            'device_id' => $pendingData['device_id'] ?? null,
            'device_name' => $pendingData['device_name'] ?? null,
        ];
    }

    /**
     * Resend OTP for pending registration
     */
    public function resendPendingOtp(string $email): array
    {
        // ... (existing logic, maybe need update for link resend?)
        // The user asked about link registration not working, resend is separate issue.
        // For now, let's stick to fixing the registration flow.

        $key = $this->pendingRegistrationKey($email);
        $pendingData = Cache::get($key);

        if (!$pendingData) {
            // Try to find if there was a token-based pending reg?
            // Without email->token mapping, we can't easily find pending link data by email.
            // But usually pending flow uses email as identifier for OTP. 
            // If using LINK, we keyed by token.
            // To support Resend for LINK, we should have stored a mapping or used email key for link too.
            // For now, let's fix the PRIMARY flow first.
            return ['success' => false, 'message' => 'No pending registration found'];
        }

        // ... existing OTP resend logic
        // Generate new OTP
        $code = $this->otpGenerator->generate(config('authmaster.otp.length', 6));
        $pendingData['otp'] = $code;

        $ttl = config('authmaster.registration.verification_expires', 3600);
        Cache::put($key, $pendingData, $ttl);

        try {
            $tempUser = (object) ['name' => $pendingData['name'], 'email' => $email];
            Mail::to($email)->send(new SendOtpMail($tempUser, $code));
            return ['success' => true, 'message' => 'New verification code sent'];
        } catch (\Throwable $e) {
            return ['success' => false, 'message' => 'Failed to send verification email'];
        }
    }

    /**
     * Check if pending registration should be used
     */
    public function isPendingFlowEnabled(): bool
    {
        $method = $this->getVerificationMethod();
        return ($method === 'otp' || $method === 'link')
            && config('authmaster.registration.verify_before_create', true);
    }
}
