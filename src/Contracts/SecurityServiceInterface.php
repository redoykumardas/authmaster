<?php

namespace Redoy\AuthMaster\Contracts;

interface SecurityServiceInterface
{
    /**
     * Check if a login attempt should be allowed.
     *
     * @param string|null $email The user's email
     * @param string $ip The request IP address
     * @return bool Whether the login attempt is allowed
     */
    public function allowLoginAttempt(?string $email, string $ip): bool;

    /**
     * Record a failed login attempt.
     *
     * @param string|null $email The user's email
     * @param string $ip The request IP address
     */
    public function recordFailedAttempt(?string $email, string $ip): void;

    /**
     * Clear failed login attempts for a user.
     *
     * @param string $email The user's email
     */
    public function clearFailedAttempts(string $email): void;
}
