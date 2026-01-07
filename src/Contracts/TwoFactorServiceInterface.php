<?php

namespace Redoy\AuthMaster\Contracts;

interface TwoFactorServiceInterface
{
    /**
     * Generate and send a 2FA OTP to the user.
     *
     * @param mixed $user The user instance
     * @param string|null $deviceId Optional device identifier
     * @return array Result with success status
     */
    public function generateAndSend($user, ?string $deviceId = null): array;

    /**
     * Verify a 2FA OTP code.
     *
     * @param mixed $user The user instance
     * @param string $code The OTP code to verify
     * @param string|null $deviceId Optional device identifier
     * @return array Result with success status
     */
    public function verify($user, string $code, ?string $deviceId = null): array;

    /**
     * Check if 2FA is required for a user.
     *
     * @param mixed $user The user instance
     * @return bool Whether 2FA is required
     */
    public function isTwoFactorRequiredFor($user): bool;
}
