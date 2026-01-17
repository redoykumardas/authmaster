<?php

namespace Redoy\AuthMaster\Contracts;

interface PasswordServiceInterface
{
    /**
     * Send a password reset link to the user's email.
     *
     * @param string $email The user's email address
     * @return void
     * @throws \Redoy\AuthMaster\Exceptions\AuthException
     */
    public function sendResetLink(string $email): void;

    /**
     * Reset the user's password.
     *
     * @param array $payload Contains email, password, and token
     * @return void
     * @throws \Redoy\AuthMaster\Exceptions\AuthException
     */
    public function resetPassword(array $payload): void;
}
