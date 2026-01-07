<?php

namespace Redoy\AuthMaster\Contracts;

use Redoy\AuthMaster\DTOs\AuthResult;
use Redoy\AuthMaster\DTOs\RegisterData;
use Redoy\AuthMaster\DTOs\VerifyEmailData;

interface RegistrationServiceInterface
{
    /**
     * Register a new user.
     *
     * @param RegisterData $data Registration data
     * @return AuthResult The registration result
     * @throws \Redoy\AuthMaster\Exceptions\AuthException On failure
     */
    public function register(RegisterData $data): AuthResult;

    /**
     * Verify email address.
     *
     * @param VerifyEmailData $data Verification data
     * @return AuthResult The verification result
     * @throws \Redoy\AuthMaster\Exceptions\VerificationFailedException On failure
     */
    public function verifyEmail(VerifyEmailData $data): AuthResult;

    /**
     * Resend verification to user.
     *
     * @param mixed $user The user instance
     * @return void
     * @throws \Redoy\AuthMaster\Exceptions\AuthException On failure
     */
    public function resendVerification($user): void;
}
