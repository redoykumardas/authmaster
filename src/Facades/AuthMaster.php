<?php

namespace Redoy\AuthMaster\Facades;

use Illuminate\Support\Facades\Facade;
use Redoy\AuthMaster\Contracts\AuthManagerInterface;

/**
 * @method static string extractDeviceId(\Illuminate\Http\Request $request)
 * @method static \Redoy\AuthMaster\DTOs\AuthResult loginWithData(\Redoy\AuthMaster\DTOs\LoginData $data)
 * @method static \Redoy\AuthMaster\DTOs\AuthResult finalizeLoginFromData($user, string $deviceId, ?string $deviceName = null, ?string $ipAddress = null, ?string $userAgent = null)
 * @method static void logoutCurrentDevice(\Illuminate\Http\Request $request)
 * @method static void logoutAllDevices(\Illuminate\Http\Request $request)
 * @method static \Redoy\AuthMaster\DTOs\AuthResult updateProfile($user, array $data)
 * @method static \Redoy\AuthMaster\DTOs\AuthResult changePassword($user, array $payload)
 * 
 * @see \Redoy\AuthMaster\Services\AuthManager
 */
class AuthMaster extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return AuthManagerInterface::class;
    }
}
