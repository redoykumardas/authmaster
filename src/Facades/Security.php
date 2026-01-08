<?php

namespace Redoy\AuthMaster\Facades;

use Illuminate\Support\Facades\Facade;
use Redoy\AuthMaster\Contracts\SecurityServiceInterface;

/**
 * @method static bool allowLoginAttempt(?string $email, string $ip, string $deviceId)
 * @method static void recordFailedAttempt(?string $email, string $ip, string $deviceId)
 * @method static void clearFailedAttempts(string $email, ?string $deviceId = null)
 * @method static bool allowRegistrationAttempt(string $ip, string $deviceId)
 * 
 * @see \Redoy\AuthMaster\Services\SecurityService
 */
class Security extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return SecurityServiceInterface::class;
    }
}
