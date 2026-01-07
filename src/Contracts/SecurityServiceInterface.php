<?php

namespace Redoy\AuthMaster\Contracts;

interface SecurityServiceInterface
{
    /**
     * Check if a login attempt should be allowed.
     */
    public function allowLoginAttempt(?string $email, string $ip, ?string $deviceId = null): bool;

    /**
     * Record a failed login attempt.
     */
    public function recordFailedAttempt(?string $email, string $ip, ?string $deviceId = null): void;

    /**
     * Clear failed login attempts for a user.
     */
    public function clearFailedAttempts(string $email, ?string $deviceId = null): void;

    /**
     * Check if registration attempt is allowed from this device/IP.
     */
    public function allowRegistrationAttempt(string $ip, ?string $deviceId = null): bool;

    /**
     * Record a registration attempt.
     */
    public function recordRegistrationAttempt(string $ip, ?string $deviceId = null): void;
}
