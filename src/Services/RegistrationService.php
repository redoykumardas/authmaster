<?php

namespace Redoy\AuthMaster\Services;

use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Support\Facades\Auth;
use Redoy\AuthMaster\Contracts\AuthManagerInterface;
use Redoy\AuthMaster\Contracts\EmailVerificationServiceInterface;
use Redoy\AuthMaster\Contracts\RegistrationServiceInterface;
use Redoy\AuthMaster\Contracts\SecurityServiceInterface;
use Redoy\AuthMaster\DTOs\AuthResult;
use Redoy\AuthMaster\DTOs\RegisterData;
use Redoy\AuthMaster\DTOs\VerifyEmailData;
use Redoy\AuthMaster\Exceptions\AuthException;
use Redoy\AuthMaster\Exceptions\TooManyAttemptsException;
use Redoy\AuthMaster\Exceptions\VerificationFailedException;

class RegistrationService implements RegistrationServiceInterface
{
    protected $userModel;

    public function __construct(
        protected AuthManagerInterface $authManager,
        protected EmailVerificationServiceInterface $emailVerification,
        protected SecurityServiceInterface $securityService,
        protected Hasher $hasher
    ) {
        $this->userModel = config('auth.providers.users.model');
    }

    public function register(RegisterData $data): AuthResult
    {
        // Enforce device-based registration limit
        $this->securityService->allowRegistrationAttempt($data->ipAddress, $data->deviceId);

        $this->securityService->recordRegistrationAttempt($data->ipAddress, $data->deviceId);

        return $this->handleRegistration($data);
    }

    /**
     * Determine the registration flow and handle accordingly.
     */
    protected function handleRegistration(RegisterData $data): AuthResult
    {
        // If verification is required, use pending registration flow (stores in cache/pending table)
        if ($this->emailVerification->isVerificationRequired()) {
            return $this->handlePendingRegistration($data);
        }

        // No verification required: create user immediately
        return $this->handleStandardRegistration($data);
    }

    protected function handlePendingRegistration(RegisterData $data): AuthResult
    {
        $result = $this->emailVerification->storePendingRegistration([
            'name' => $data->name,
            'email' => $data->email,
            'password' => $this->hasher->make($data->password),
            'device_id' => $data->deviceId,
            'device_name' => $data->deviceName,
            'ip_address' => $data->ipAddress,
            'user_agent' => $data->userAgent,
        ]);

        return new AuthResult(
            user: null,
            message: 'Verification sent. Please check your email to complete registration.',
            emailVerificationRequired: true,
            emailVerificationMethod: $this->emailVerification->getVerificationMethod(),
            pendingRegistration: true,
            devVerificationUrl: $result['dev_verification_url'] ?? null,
            devToken: $result['dev_token'] ?? null,
            status: 200,
        );
    }

    protected function handleStandardRegistration(RegisterData $data): AuthResult
    {
        $user = $this->userModel::create([
            'name' => $data->name,
            'email' => $data->email,
            'password' => $this->hasher->make($data->password),
        ]);

        Auth::login($user);

        $tokenResult = $this->authManager->finalizeLoginFromData(
            $user,
            $data->deviceId,
            $data->deviceName,
            $data->ipAddress,
            $data->userAgent
        );

        return new AuthResult(
            user: $user,
            token: $tokenResult->token ?? null,
            message: 'Registered successfully',
            status: 201,
        );
    }

    public function verifyEmail(VerifyEmailData $data): AuthResult
    {
        return match ($data->method) {
            'otp' => $this->verifyOtp($data),
            'link' => $this->verifyLink($data),
            default => throw new AuthException('Email verification not configured', 400),
        };
    }

    protected function verifyOtp(VerifyEmailData $data): AuthResult
    {
        // Only pending registration is supported if verification is required
        $result = $this->emailVerification->verifyPendingRegistration($data->email, $data->code);

        $user = $result['user'];
        Auth::login($user);

        $tokenResult = $this->authManager->finalizeLoginFromData(
            $user,
            $result['device_id'] ?? $data->deviceId,
            $result['device_name'] ?? $data->deviceName,
            $result['ip_address'] ?? $data->ipAddress,
            $result['user_agent'] ?? $data->userAgent
        );

        return new AuthResult(
            user: $user,
            token: $tokenResult->token ?? null,
            message: $result['message'],
            status: 201,
        );
    }

    protected function verifyLink(VerifyEmailData $data): AuthResult
    {
        // Only pending flow is supported for registration verification
        $result = $this->emailVerification->verifyPendingLink($data->token);

        $user = $result['user'];
        Auth::login($user);

        $tokenResult = $this->authManager->finalizeLoginFromData(
            $user,
            $result['device_id'] ?? $data->deviceId,
            $result['device_name'] ?? $data->deviceName,
            $result['ip_address'] ?? $data->ipAddress,
            $result['user_agent'] ?? $data->userAgent
        );

        return new AuthResult(
            user: $user,
            token: $tokenResult->token ?? null,
            message: $result['message'],
            status: 201,
        );
    }

}
