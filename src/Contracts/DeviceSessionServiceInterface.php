<?php

namespace Redoy\AuthMaster\Contracts;

use Illuminate\Http\Request;

interface DeviceSessionServiceInterface
{
    /**
     * Create or update a device session for a user.
     *
     * @param mixed $user The user instance
     * @param string $deviceId The device identifier
     * @param Request $request The HTTP request
     * @param mixed $tokenId Optional token ID
     * @param array $tokenData Token metadata
     * @param string|null $deviceName Optional device name
     * @return object The session object
     */
    public function createOrUpdateSession(
        $user,
        string $deviceId,
        Request $request,
        $tokenId = null,
        array $tokenData = [],
        string $deviceName = null
    );

    /**
     * Create or update a device session without a Request object (for DTO-based flows).
     *
     * @param mixed $user The user instance
     * @param string $deviceId The device identifier
     * @param mixed $tokenId Optional token ID
     * @param array $tokenData Token metadata
     * @param string|null $deviceName Optional device name
     * @param string|null $ipAddress Optional IP address
     * @param string|null $userAgent Optional user agent
     * @return object The session object
     */
    public function createOrUpdateSessionFromData(
        $user,
        string $deviceId,
        $tokenId = null,
        array $tokenData = [],
        ?string $deviceName = null,
        ?string $ipAddress = null,
        ?string $userAgent = null
    );

    /**
     * Enforce the maximum device limit for a user.
     *
     * @param mixed $user The user instance
     */
    public function enforceDeviceLimit($user): void;

    /**
     * Invalidate a specific device session.
     *
     * @param mixed $user The user instance
     * @param string $deviceId The device identifier
     */
    public function invalidateSession($user, string $deviceId): void;

    /**
     * Invalidate all device sessions for a user.
     *
     * @param mixed $user The user instance
     */
    public function invalidateAllSessions($user): void;

    /**
     * Get all active sessions for a user.
     *
     * @param mixed $user The user instance
     * @return \Illuminate\Support\Collection
     */
    public function getActiveSessions($user);
}
