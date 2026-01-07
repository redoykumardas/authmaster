<?php

namespace Redoy\AuthMaster\Services;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Redoy\AuthMaster\Contracts\AuthManagerInterface;
use Redoy\AuthMaster\Contracts\EmailVerificationServiceInterface;
use Redoy\AuthMaster\Contracts\RegistrationServiceInterface;
use Redoy\AuthMaster\DTOs\AuthResult;
use Redoy\AuthMaster\DTOs\RegisterData;
use Redoy\AuthMaster\DTOs\VerifyEmailData;
use Redoy\AuthMaster\Exceptions\AuthException;
use Redoy\AuthMaster\Exceptions\VerificationFailedException;

class RegistrationService implements RegistrationServiceInterface
{
    public function __construct(
        protected AuthManagerInterface $authManager,
        protected EmailVerificationServiceInterface $emailVerification
    ) {
    }

    public function register(RegisterData $data): AuthResult
    {
        // Check if pending registration flow is enabled
        if ($this->emailVerification->isPendingFlowEnabled()) {
            return $this->handlePendingRegistration($data);
        }

        // Standard flow: create user immediately
        return $this->handleStandardRegistration($data);
    }

    protected function handlePendingRegistration(RegisterData $data): AuthResult
    {
        $result = $this->emailVerification->storePendingRegistration([
            'name' => $data->name,
            'email' => $data->email,
            'password' => Hash::make($data->password),
            'device_id' => $data->deviceId,
            'device_name' => $data->deviceName,
        ]);

        if (!$result['success']) {
            throw new AuthException($result['message'] ?? 'Registration failed', 422);
        }

        return new AuthResult(
            user: null,
            message: 'Verification sent. Please check your email to complete registration.',
            emailVerificationRequired: true,
            emailVerificationMethod: $this->emailVerification->getVerificationMethod(),
            pendingRegistration: true,
            devVerificationUrl: $result['dev_verification_url'] ?? null,
            devToken: $result['dev_token'] ?? null,
        );
    }

    protected function handleStandardRegistration(RegisterData $data): AuthResult
    {
        $userModel = config('auth.providers.users.model');
        $user = new $userModel();
        $user->name = $data->name;
        $user->email = $data->email;
        $user->password = Hash::make($data->password);
        $user->save();

        Auth::login($user);

        // Check if email verification is required
        if ($this->emailVerification->isVerificationRequired()) {
            $this->emailVerification->sendVerification($user);

            $tokenResult = $this->authManager->finalizeLoginFromData($user, $data->deviceId, $data->deviceName);

            return new AuthResult(
                user: $user,
                token: $tokenResult['token'] ?? null,
                message: 'Registered. Please verify your email.',
                emailVerificationRequired: true,
                emailVerificationMethod: $this->emailVerification->getVerificationMethod(),
            );
        }

        $tokenResult = $this->authManager->finalizeLoginFromData($user, $data->deviceId, $data->deviceName);

        return new AuthResult(
            user: $user,
            token: $tokenResult['token'] ?? null,
            message: 'Registered successfully',
        );
    }

    public function verifyEmail(VerifyEmailData $data): AuthResult
    {
        if ($data->method === 'otp') {
            return $this->verifyOtp($data);
        }

        if ($data->method === 'link') {
            return $this->verifyLink($data);
        }

        throw new AuthException('Email verification not configured', 400);
    }

    protected function verifyOtp(VerifyEmailData $data): AuthResult
    {
        // Check pending registration first
        if ($this->emailVerification->isPendingFlowEnabled()) {
            $result = $this->emailVerification->verifyPendingRegistration($data->email, $data->code);

            if ($result['success']) {
                $user = $result['user'];
                Auth::login($user);

                $tokenResult = $this->authManager->finalizeLoginFromData(
                    $user,
                    $result['device_id'] ?? $data->deviceId,
                    $result['device_name'] ?? $data->deviceName
                );

                return new AuthResult(
                    user: $user,
                    token: $tokenResult['token'] ?? null,
                    message: $result['message'],
                );
            }

            if ($result['message'] !== 'No pending registration found or it has expired') {
                throw new VerificationFailedException($result['message']);
            }
        }

        // Existing user verification
        $userModel = config('auth.providers.users.model');
        $user = $userModel::where('email', $data->email)->first();

        if (!$user) {
            throw new VerificationFailedException('No pending registration or user found for this email');
        }

        $result = $this->emailVerification->verifyOtp($user, $data->code);

        if (!$result['success']) {
            throw new VerificationFailedException($result['message']);
        }

        return new AuthResult(
            user: $user,
            message: $result['message'],
        );
    }

    protected function verifyLink(VerifyEmailData $data): AuthResult
    {
        // Check pending flow first
        if ($this->emailVerification->isPendingFlowEnabled()) {
            $result = $this->emailVerification->verifyPendingLink($data->token);

            if ($result['success']) {
                $user = $result['user'];
                Auth::login($user);

                $tokenResult = $this->authManager->finalizeLoginFromData(
                    $user,
                    $result['device_id'] ?? $data->deviceId,
                    $result['device_name'] ?? $data->deviceName
                );

                return new AuthResult(
                    user: $user,
                    token: $tokenResult['token'] ?? null,
                    message: $result['message'],
                );
            }
        }

        // Standard verification
        $result = $this->emailVerification->verifyLink($data->token);

        if (!$result['success']) {
            throw new VerificationFailedException($result['message']);
        }

        return new AuthResult(
            user: $result['user'] ?? null,
            message: $result['message'],
        );
    }

    public function resendVerification($user): void
    {
        if ($this->emailVerification->isVerified($user)) {
            throw new AuthException('Email already verified', 400);
        }

        $result = $this->emailVerification->sendVerification($user);

        if (!$result['success']) {
            throw new AuthException($result['message'] ?? 'Failed to send verification', 422);
        }
    }
}
