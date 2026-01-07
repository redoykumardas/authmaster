<?php

namespace Redoy\AuthMaster\Contracts;

interface ValidationManagerInterface
{
    /**
     * Get validation rules for login.
     *
     * @return array Validation rules
     */
    public function rulesForLogin(): array;

    /**
     * Get validation rules for registration.
     *
     * @return array Validation rules
     */
    public function rulesForRegister(): array;

    /**
     * Get validation rules for profile update.
     *
     * @param mixed $user The user instance
     * @return array Validation rules
     */
    public function rulesForProfileUpdate($user): array;

    /**
     * Get validation rules for password change.
     *
     * @return array Validation rules
     */
    public function rulesForChangePassword(): array;

    /**
     * Get validation rules for password reset email.
     *
     * @return array Validation rules
     */
    public function rulesForPasswordEmail(): array;

    /**
     * Get validation rules for password reset.
     *
     * @return array Validation rules
     */
    public function rulesForPasswordReset(): array;

    /**
     * Get validation rules for 2FA send.
     *
     * @return array Validation rules
     */
    public function rulesFor2FASend(): array;

    /**
     * Get validation rules for 2FA verification.
     *
     * @return array Validation rules
     */
    public function rulesFor2FAVerify(): array;
}
