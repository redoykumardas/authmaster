<?php

namespace Redoy\AuthMaster\Contracts;

interface EmailVerificationServiceInterface
{
    /**
     * Get the configured verification method.
     *
     * @return string The verification method ('otp', 'link', or 'none')
     */
    public function getVerificationMethod(): string;

    /**
     * Check if email verification is required.
     *
     * @return bool Whether verification is required
     */
    public function isVerificationRequired(): bool;

    /**
     * Check if a user's email is verified.
     *
     * @param mixed $user The user instance
     * @return bool Whether the email is verified
     */
    public function isVerified($user): bool;

    /**
     * Mark a user's email as verified.
     *
     * @param mixed $user The user instance
     */
    public function markAsVerified($user): void;


    /**
     * Store pending registration data.
     *
     * @param array $data Registration data
     * @return array Result with success status
     */
    public function storePendingRegistration(array $data): array;

    /**
     * Verify pending registration with OTP.
     *
     * @param string $email The email address
     * @param string $code The OTP code
     * @return array Result with user if successful
     */
    public function verifyPendingRegistration(string $email, string $code): array;

    /**
     * Verify pending registration with link token.
     *
     * @param string $token The verification token
     * @return array Result with user if successful
     */
    public function verifyPendingLink(string $token): array;

    /**
     * Resend OTP for pending registration.
     *
     * @param string $email The email address
     * @return array Result with success status
     */
    public function resendPendingOtp(string $email): array;

}
