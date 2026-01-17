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
        protected Hasher $hasher,
        protected ?RegisterData $registerData = null
    ) {
        $this->userModel = config('auth.providers.users.model');
    }

    public function register(): AuthResult
    {

        // Enforce device-based registration limit
        $this->securityService->allowRegistrationAttempt();

        $this->securityService->recordRegistrationAttempt();

        return $this->handleRegistration();
    }

    /**
     * Determine the registration flow and handle accordingly.
     */
    protected function handleRegistration(): AuthResult
    {
        // If verification is required, use pending registration flow (stores in cache/pending table)
        if ($this->emailVerification->isVerificationRequired()) {
            return $this->handlePendingRegistration();
        }

        // No verification required: create user immediately
        return $this->handleStandardRegistration();
    }

    protected function handlePendingRegistration(): AuthResult
    {
        $result = $this->emailVerification->storePendingRegistration();

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

    protected function handleStandardRegistration(): AuthResult
    {
        $user = $this->userModel::create([
            'name' => $this->registerData->name,
            'email' => $this->registerData->email,
            'password' => $this->hasher->make($this->registerData->password),
        ]);

        return $this->authenticateAndRespond(
            $user,
            $this->registerData->deviceId,
            $this->registerData->deviceName,
            $this->registerData->ipAddress,
            $this->registerData->userAgent,
            'Registered successfully'
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

        return $this->authenticateAndRespond(
            $result['user'],
            $result['device_id'] ?? $data->deviceId,
            $result['device_name'] ?? $data->deviceName,
            $result['ip_address'] ?? $data->ipAddress,
            $result['user_agent'] ?? $data->userAgent,
            $result['message']
        );
    }

    protected function verifyLink(VerifyEmailData $data): AuthResult
    {
        // Only pending flow is supported for registration verification
        $result = $this->emailVerification->verifyPendingLink($data->token);

        return $this->authenticateAndRespond(
            $result['user'],
            $result['device_id'] ?? $data->deviceId,
            $result['device_name'] ?? $data->deviceName,
            $result['ip_address'] ?? $data->ipAddress,
            $result['user_agent'] ?? $data->userAgent,
            $result['message']
        );
    }

    protected function authenticateAndRespond($user, $deviceId, $deviceName, $ipAddress, $userAgent, $message): AuthResult
    {
        Auth::login($user);

        $tokenResult = $this->authManager->finalizeLoginFromData(
            $user,
            $deviceId,
            $deviceName,
            $ipAddress,
            $userAgent
        );

        return new AuthResult(
            user: $user,
            token: $tokenResult->token ?? null,
            message: $message,
            status: 201,
        );
    }

}
