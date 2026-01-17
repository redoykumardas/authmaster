<?php

namespace Redoy\AuthMaster\Contracts;

use Illuminate\Http\Request;
use Redoy\AuthMaster\DTOs\AuthResult;

interface AuthManagerInterface
{
    /**
     * Extract device ID from request.
     *
     * @param Request $request The HTTP request
     * @return string The device identifier
     */
    public function extractDeviceId(Request $request): string;


    /**
     * Authenticate a user with DTO data.
     *
     * @param \Redoy\AuthMaster\DTOs\LoginData $data Login data
     * @return AuthResult Result with user and token data
     * @throws \Redoy\AuthMaster\Exceptions\AuthException On failure
     */
    public function loginWithData(\Redoy\AuthMaster\DTOs\LoginData $data): AuthResult;


    /**
     * Finalize login using device data directly (for DTO-based flows).
     *
     * @param mixed $user The authenticated user
     * @param string $deviceId The device identifier
     * @param string|null $deviceName Optional device name
     * @param string|null $ipAddress Optional IP address
     * @param string|null $userAgent Optional user agent
     * @return AuthResult Result with token data
     */
    public function finalizeLoginFromData($user, string $deviceId, ?string $deviceName = null, ?string $ipAddress = null, ?string $userAgent = null): AuthResult;


    /**
     * Logout from the current device.
     *
     * @param Request $request The HTTP request
     */
    public function logoutCurrentDevice(Request $request): void;

    /**
     * Logout from all devices.
     *
     * @param Request $request The HTTP request
     */
    public function logoutAllDevices(Request $request): void;

    /**
     * Update user profile.
     *
     * @param mixed $user The user instance
     * @param array $data Profile data to update
     * @return AuthResult The updated user result
     */
    public function updateProfile($user, array $data): AuthResult;

    /**
     * Change user password.
     *
     * @param mixed $user The user instance
     * @param array $payload Password change data
     * @return AuthResult Result with success status
     */
    public function changePassword($user, array $payload): AuthResult;

    /**
     * Send password reset link.
     *
     * @param array $payload Contains email
     * @return AuthResult Result with success status
     */
    public function sendPasswordResetLink(array $payload): AuthResult;


    /**
     * Reset user password with DTO data.
     *
     * @param \Redoy\AuthMaster\DTOs\PasswordResetData $data Password reset data
     * @return AuthResult Result with success status
     */
    public function resetPasswordWithData(\Redoy\AuthMaster\DTOs\PasswordResetData $data): AuthResult;


    /**
     * Verify 2FA code.
     *
     * @param mixed $user The user instance
     * @param string $code The 2FA code
     * @return AuthResult Result with success status
     */
    public function verifyTwoFactor($user, $code): AuthResult;

    /**
     * Verify 2FA code and finalize login.
     *
     * @param string $tempToken The temporary session token
     * @param string $code The 2FA code
     * @param string $deviceId
     * @param string|null $deviceName
     * @param string $ipAddress
     * @param string|null $userAgent
     * @return AuthResult Result with user/token data
     */
    public function verifyTwoFactorLogin(string $tempToken, string $code, string $deviceId, ?string $deviceName, string $ipAddress, ?string $userAgent): AuthResult;


    /**
     * Get social login redirect URL.
     *
     * @param string $provider The social provider
     * @return AuthResult Result with redirect URL
     */
    public function socialRedirect($provider): AuthResult;

    /**
     * Handle social login callback.
     *
     * @param string $provider The social provider
     * @param Request $request The HTTP request
     * @return AuthResult Result with user/token data
     */
    public function handleSocialCallback($provider, Request $request): AuthResult;
    /**
     * Get all logged in devices for the user.
     *
     * @param mixed $user
     * @return \Illuminate\Support\Collection
     */
    public function getDevices($user);

    /**
     * Remove/Logout a specific device for the user.
     *
     * @param mixed $user
     * @param string $deviceId
     */
    public function removeDevice($user, string $deviceId): void;
}
