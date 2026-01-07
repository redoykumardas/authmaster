<?php

namespace Redoy\AuthMaster\Contracts;

use Illuminate\Http\Request;

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
     * Authenticate a user with credentials.
     *
     * @param Request $request The HTTP request with credentials
     * @return array Result with success status and user/token data
     */
    public function login(Request $request): array;

    /**
     * Authenticate a user with DTO data.
     *
     * @param \Redoy\AuthMaster\DTOs\LoginData $data Login data
     * @return array Result with user and token data
     * @throws \Redoy\AuthMaster\Exceptions\AuthException On failure
     */
    public function loginWithData(\Redoy\AuthMaster\DTOs\LoginData $data): array;

    /**
     * Finalize login process after authentication.
     *
     * @param mixed $user The authenticated user
     * @param Request $request The HTTP request
     * @param string $deviceId The device identifier
     * @param string|null $deviceName Optional device name
     * @return array Result with token data
     */
    public function finalizeLogin($user, Request $request, string $deviceId, string $deviceName = null): array;

    /**
     * Finalize login using device data directly (for DTO-based flows).
     *
     * @param mixed $user The authenticated user
     * @param string $deviceId The device identifier
     * @param string|null $deviceName Optional device name
     * @return array Result with token data
     */
    public function finalizeLoginFromData($user, string $deviceId, ?string $deviceName = null): array;

    /**
     * Register a new user.
     *
     * @param Request $request The HTTP request with registration data
     * @return array Result with success status and user/token data
     */
    public function register(Request $request): array;

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
     * @return mixed The updated user
     */
    public function updateProfile($user, array $data);

    /**
     * Change user password.
     *
     * @param mixed $user The user instance
     * @param array $payload Password change data
     * @return array Result with success status
     */
    public function changePassword($user, array $payload): array;

    /**
     * Send password reset link.
     *
     * @param array $payload Contains email
     * @return array Result with success status
     */
    public function sendPasswordResetLink(array $payload): array;

    /**
     * Reset user password.
     *
     * @param array $payload Password reset data
     * @return array Result with success status
     */
    public function resetPassword(array $payload): array;

    /**
     * Reset user password with DTO data.
     *
     * @param \Redoy\AuthMaster\DTOs\PasswordResetData $data Password reset data
     * @return array Result with success status
     */
    public function resetPasswordWithData(\Redoy\AuthMaster\DTOs\PasswordResetData $data): array;

    /**
     * Send 2FA code to user.
     *
     * @param mixed $user The user instance
     * @return array Result with success status
     */
    public function sendTwoFactor($user): array;

    /**
     * Verify 2FA code.
     *
     * @param mixed $user The user instance
     * @param string $code The 2FA code
     * @return array Result with success status
     */
    public function verifyTwoFactor($user, $code): array;

    /**
     * Get social login redirect URL.
     *
     * @param string $provider The social provider
     * @return array Result with redirect URL
     */
    public function socialRedirect($provider): array;

    /**
     * Handle social login callback.
     *
     * @param string $provider The social provider
     * @param Request $request The HTTP request
     * @return array Result with user/token data
     */
    public function handleSocialCallback($provider, Request $request): array;
}
