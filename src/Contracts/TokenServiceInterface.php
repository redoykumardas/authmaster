<?php

namespace Redoy\AuthMaster\Contracts;

interface TokenServiceInterface
{
    /**
     * Create an authentication token for a user.
     *
     * @param mixed $user The user instance
     * @param string|null $deviceId Optional device identifier
     * @return array Token data including access_token, token_type, expires_at
     */
    public function createTokenForUser($user, string $deviceId = null): array;
}
