<?php

namespace Redoy\AuthMaster\Contracts;

interface PasswordServiceInterface
{
    /**
     * Send a password reset link to the user's email.
     *
     * @param string $email The user's email address
     * @return array Result with success status and optional message
     */
    public function sendResetLink(string $email): array;

    /**
     * Reset the user's password.
     *
     * @param array $payload Contains email, password, and token
     * @return array Result with success status and optional message
     */
    public function resetPassword(array $payload): array;
}
