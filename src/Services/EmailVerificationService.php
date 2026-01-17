<?php

namespace Redoy\AuthMaster\Services;

use Illuminate\Contracts\Bus\Dispatcher;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Support\Str;
use Redoy\AuthMaster\Contracts\EmailVerificationServiceInterface;
use Redoy\AuthMaster\Contracts\OtpGeneratorInterface;
use Redoy\AuthMaster\DTOs\RegisterData;
use Redoy\AuthMaster\Exceptions\AuthException;
use Redoy\AuthMaster\Exceptions\VerificationFailedException;
use Redoy\AuthMaster\Jobs\SendOtpJob;
use Redoy\AuthMaster\Jobs\SendVerificationLinkJob;

class EmailVerificationService implements EmailVerificationServiceInterface
{
    protected string $userModel;

    /**
     * Create a new service instance.
     *
     * @param OtpGeneratorInterface $otpGenerator
     * @param Hasher $hasher
     * @param ConfigRepository $config
     * @param CacheRepository $cache
     * @param Dispatcher $dispatcher
     * @param RegisterData|null $registerData
     */
    public function __construct(
        protected OtpGeneratorInterface $otpGenerator,
        protected Hasher $hasher,
        protected ConfigRepository $config,
        protected CacheRepository $cache,
        protected Dispatcher $dispatcher,
        protected ?RegisterData $registerData = null
    ) {
        $this->userModel = $this->config->get('auth.providers.users.model');
    }

    // =========================================================================
    // 1. Configuration & Status Checks
    // =========================================================================

    /**
     * Get the configured verification method (e.g., 'otp', 'link', 'none').
     *
     * @return string
     */
    public function getVerificationMethod(): string
    {
        return $this->config->get('authmaster.registration.email_verification', 'none');
    }

    /**
     * Check if email verification is required.
     *
     * @return bool
     */
    public function isVerificationRequired(): bool
    {
        return $this->getVerificationMethod() !== 'none';
    }

    /**
     * Check if the given user is already verified.
     *
     * @param mixed $user
     * @return bool
     */
    public function isVerified($user): bool
    {
        return !is_null($user->email_verified_at);
    }

    /**
     * Mark the given user as verified.
     *
     * @param mixed $user
     * @return void
     */
    public function markAsVerified($user): void
    {
        $user->forceFill([
            'email_verified_at' => now(),
        ])->save();
    }

    // =========================================================================
    // 2. Cache Key Management
    // =========================================================================

    protected function resendCooldownKey($identifier): string
    {
        return "authmaster_resend_cooldown:" . md5($identifier);
    }

    protected function pendingRegistrationKey(string $email): string
    {
        return "authmaster_pending_reg:" . md5($email);
    }

    protected function verificationAttemptsKey(string $email): string
    {
        return "authmaster_otp_attempts:" . md5($email);
    }

    protected function ipAttemptsKey(string $ip): string
    {
        return "authmaster_ip_attempts:" . md5($ip);
    }

    // =========================================================================
    // 3. Resend & Cooldown Logic
    // =========================================================================

    /**
     * Check if a resend is currently allowed or if the user is in a cooldown period.
     *
     * @param string $identifier
     * @return int|null Seconds remaining if in cooldown, null otherwise.
     */
    protected function checkResendDelay(string $identifier): ?int
    {
        $key = $this->resendCooldownKey($identifier);
        $expiresAt = $this->cache->get($key);

        if ($expiresAt && now()->timestamp < $expiresAt) {
            return $expiresAt - now()->timestamp;
        }

        return null;
    }

    /**
     * Set the resend cooldown for an identifier.
     *
     * @param string $identifier
     * @return void
     */
    protected function setResendDelay(string $identifier): void
    {
        $delay = $this->config->get('authmaster.otp.resend_delay_seconds', 60);
        $key = $this->resendCooldownKey($identifier);
        $this->cache->put($key, now()->timestamp + $delay, $delay);
    }

    /**
     * Resend the pending OTP if allowed.
     *
     * @param string $email
     * @return array
     * @throws AuthException
     */
    public function resendPendingOtp(string $email): array
    {
        // Step 1: Check if the user is in the cooldown period
        $delay = $this->checkResendDelay($email);
        if ($delay) {
            throw new AuthException("Please wait {$delay} seconds before requesting a new code", 429);
        }

        // Step 2: Retrieve the existing pending registration data
        $key = $this->pendingRegistrationKey($email);
        $pendingData = $this->cache->get($key);

        if (!$pendingData) {
            throw new AuthException('No pending registration found', 404);
        }

        // Step 3: Generate a new OTP and update the pending data
        $code = $this->otpGenerator->generate($this->config->get('authmaster.otp.length', 6));
        $pendingData['otp'] = $code;

        $ttl = $this->config->get('authmaster.registration.verification_expires', 3600);
        $this->cache->put($key, $pendingData, $ttl);
        
        // Step 4: Reset the cooldown, clear previous attempts, and dispatch the job
        $this->setResendDelay($email);
        $this->clearVerificationAttempts($email);

        $tempUser = (object) ['name' => $pendingData['name'], 'email' => $email];
        $this->dispatchOtpJob($tempUser, $code);

        return ['message' => 'New verification code sent'];
    }

    // =========================================================================
    // 4. Registration Flow Logic
    // =========================================================================

    /**
     * Store registration data pending verification.
     *
     * @return array
     * @throws AuthException
     */
    public function storePendingRegistration(): array
    {
        $email = $this->registerData->email;

        // Step 1: Ensure no existing pending registration blocks this request
        $this->ensureNoPendingRegistration($email);

        $ttl = $this->config->get('authmaster.registration.verification_expires', 3600);
        $method = $this->getVerificationMethod();
        
        // Step 2: Prepare the data payload to be cached
        $pendingData = $this->preparePendingData($method);

        // Clear any previous attempts for this new registration
        $this->clearVerificationAttempts($email);

        // Step 3: Handle the specific verification method (OTP or Link)
        return match ($method) {
            'otp' => $this->handleOtpVerification($email, $pendingData, $ttl),
            'link' => $this->handleLinkVerification($email, $pendingData, $ttl),
            default => throw new AuthException('Invalid verification method', 400),
        };
    }

    /**
     * Check if there is already a pending registration for this email.
     *
     * @param string $email
     * @return bool
     */
    public function hasPendingRegistration(string $email): bool
    {
        $key = $this->pendingRegistrationKey($email);
        return $this->cache->has($key);
    }

    /**
     * Ensure the email is not already processing a registration.
     *
     * @param string $email
     * @return void
     * @throws AuthException
     */
    protected function ensureNoPendingRegistration(string $email): void
    {
        if ($this->hasPendingRegistration($email)) {
            throw new AuthException('Your email is in registration process, verify otp or wait some time and try again.', 429);
        }
    }

    /**
     * Prepare the array of data to be cached for pending registration.
     *
     * @param string $method
     * @return array
     */
    protected function preparePendingData(string $method): array
    {
        return [
            'name' => $this->registerData->name,
            'email' => $this->registerData->email,
            'password' => $this->hasher->make($this->registerData->password),
            'created_at' => now()->toISOString(),
            'method' => $method,
            'device_id' => $this->registerData->deviceId,
            'device_name' => $this->registerData->deviceName,
            'ip_address' => $this->registerData->ipAddress,
            'user_agent' => $this->registerData->userAgent,
        ];
    }

    /**
     * Handle the OTP verification flow.
     */
    protected function handleOtpVerification(string $email, array $pendingData, int $ttl): array
    {
        $code = $this->otpGenerator->generate($this->config->get('authmaster.otp.length', 6));
        $pendingData['otp'] = $code;

        $key = $this->pendingRegistrationKey($email);
        $this->cache->put($key, $pendingData, $ttl);
        $this->setResendDelay($email);

        $tempUser = (object) ['name' => $this->registerData->name, 'email' => $email];
        $this->dispatchOtpJob($tempUser, $code);

        return ['message' => 'Verification code sent to your email'];
    }

    /**
     * Handle the Magic Link verification flow.
     */
    protected function handleLinkVerification(string $email, array $pendingData, int $ttl): array
    {
        $token = Str::random(64);
        $devToken = $this->config->get('authmaster.registration.dev_token');

        if ($devToken && !app()->isProduction()) {
            $token = $devToken;
        }

        $tokenKey = "authmaster_pending_token:{$token}";
        $this->cache->put($tokenKey, $pendingData, $ttl);
        
        // Also store by email key so ensureNoPendingRegistration works
        $emailKey = $this->pendingRegistrationKey($email);
        $this->cache->put($emailKey, $pendingData, $ttl);
        
        $this->setResendDelay($email);

        $baseUrl = $this->config->get('authmaster.registration.verification_url', '/api/auth/verify-email');
        $verificationUrl = url($baseUrl) . '?token=' . $token;

        $tempUser = (object) ['name' => $this->registerData->name, 'email' => $email];
        $this->dispatchLinkJob($tempUser, $verificationUrl);

        $result = ['message' => 'Verification link sent to your email'];

        if (!app()->isProduction()) {
            $result['dev_verification_url'] = $verificationUrl;
            $result['dev_token'] = $token;
        }

        return $result;
    }

    // =========================================================================
    // 5. Completion Logic
    // =========================================================================

    /**
     * Compute final registration by verifying the OTP.
     *
     * @param string $email
     * @param string $code
     * @return array
     * @throws VerificationFailedException
     */
    public function verifyPendingRegistration(string $email, string $code): array
        {
        $key = $this->pendingRegistrationKey($email);
        $pendingData = $this->cache->get($key);

        if (!$pendingData) {
            throw new VerificationFailedException('No pending registration found or it has expired');
        }

        // Check if max attempts exceeded
        $this->ensureNotTooManyAttempts($email);

        if (!hash_equals((string) $pendingData['otp'], (string) $code)) {
            $this->incrementVerificationAttempts($email);
            throw new VerificationFailedException('Invalid verification code');
        }

        // Clear attempts on success
        $this->clearVerificationAttempts($email);

        return $this->finalizeRegistration($pendingData, $key);
    }

    /**
     * Compute final registration by verifying the Link Token.
     *
     * @param string $token
     * @param string|null $ipAddress
     * @return array
     * @throws VerificationFailedException
     */
    public function verifyPendingLink(string $token, ?string $ipAddress = null): array
    {
        // Rate Limit Check by IP if provided
        if ($ipAddress) {
            $this->ensureIpNotBlocked($ipAddress);
        }

        $key = "authmaster_pending_token:{$token}";
        $pendingData = $this->cache->get($key);

        if (!$pendingData) {
            if ($ipAddress) {
                $this->incrementIpAttempts($ipAddress);
            }
            throw new VerificationFailedException('Verification link expired or invalid');
        }

        // Cleanup IP attempts on success (optional, but good for real users)
        if ($ipAddress) {
            $this->cache->forget($this->ipAttemptsKey($ipAddress));
        }

        return $this->finalizeRegistration($pendingData, $key);
    }

    /**
     * Finalize the user creation process after successful verification.
     *
     * @param array $pendingData
     * @param string $cacheKey
     * @return array
     * @throws VerificationFailedException
     */
    protected function finalizeRegistration(array $pendingData, string $cacheKey): array
    {
        // Step 1: Race condition check - ensure email hasn't been taken in the meantime
        if ($this->userModel::where('email', $pendingData['email'])->exists()) {
            $this->cache->forget($cacheKey);
            throw new VerificationFailedException('Email already registered');
        }

        // Step 2: Create the user in the database
        $user = $this->userModel::create([
            'name' => $pendingData['name'],
            'email' => $pendingData['email'],
            'password' => $pendingData['password'],
        ]);

        // Step 3: Mark email as verified immediately
        $this->markAsVerified($user);

        // Step 4: Cleanup cache
        $this->cache->forget($cacheKey);
        
        // Also forget the main pending registration key to unblock the email
        if (isset($pendingData['email'])) {
            $this->cache->forget($this->pendingRegistrationKey($pendingData['email']));
        }

        return [
            'message' => 'Email verified and account created successfully',
            'user' => $user,
            'device_id' => $pendingData['device_id'] ?? null,
            'device_name' => $pendingData['device_name'] ?? null,
            'ip_address' => $pendingData['ip_address'] ?? null,
            'user_agent' => $pendingData['user_agent'] ?? null,
        ];
    }

    // =========================================================================
    // 6. Job Dispatchers
    // =========================================================================

    protected function dispatchOtpJob(object $user, string $code): void
    {
        $useQueue = $this->config->get('authmaster.otp.use_queue', true);
        $job = new SendOtpJob($user, $code);

        if ($useQueue) {
            $this->dispatcher->dispatch($job);
        } else {
            $this->dispatcher->dispatchSync($job);
        }
    }

    protected function dispatchLinkJob(object $user, string $url): void
    {
        $useQueue = $this->config->get('authmaster.otp.use_queue', true);
        $job = new SendVerificationLinkJob($user, $url);

        if ($useQueue) {
            $this->dispatcher->dispatch($job);
        } else {
            $this->dispatcher->dispatchSync($job);
        }
    }

    // =========================================================================
    // 7. Max Attempts Logic
    // =========================================================================

    protected function ensureNotTooManyAttempts(string $email): void
    {
        $max = $this->config->get('authmaster.otp.max_attempts', 3);
        $key = $this->verificationAttemptsKey($email);
        $attempts = $this->cache->get($key, 0);

        if ($attempts >= $max) {
            throw new VerificationFailedException('Too many invalid attempts. Please request a new code.');
        }
    }

    protected function incrementVerificationAttempts(string $email): void
    {
        $key = $this->verificationAttemptsKey($email);
        $ttl = $this->config->get('authmaster.registration.verification_expires', 3600);
        
        $attempts = (int) $this->cache->get($key, 0) + 1;
        $this->cache->put($key, $attempts, $ttl);
    }

    protected function clearVerificationAttempts(string $email): void
    {
        $this->cache->forget($this->verificationAttemptsKey($email));
    }

    protected function ensureIpNotBlocked(string $ip): void
    {
        $max = $this->config->get('authmaster.security.max_registration_attempts_per_device', 10);
        $key = $this->ipAttemptsKey($ip);
        $attempts = $this->cache->get($key, 0);

        if ($attempts >= $max) {
             throw new VerificationFailedException('Too many failed attempts. Please try again later.');
        }
    }

    protected function incrementIpAttempts(string $ip): void
    {
        $key = $this->ipAttemptsKey($ip);
        $ttl = 3600; // Block tracking for 1 hour
        $attempts = (int) $this->cache->get($key, 0) + 1;
        $this->cache->put($key, $attempts, $ttl);
    }
}
