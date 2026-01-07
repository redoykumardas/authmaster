<?php

namespace Redoy\AuthMaster\Support;

class DeviceDetector
{
    public static function detect(string $userAgent): array
    {
        return [
            'browser' => self::getBrowser($userAgent),
            'os' => self::getOS($userAgent),
            'device_type' => self::getDeviceType($userAgent),
        ];
    }

    protected static function getBrowser(string $userAgent): string
    {
        if (str_contains($userAgent, 'MSIE'))
            return 'Internet Explorer';
        if (str_contains($userAgent, 'Firefox'))
            return 'Firefox';
        if (str_contains($userAgent, 'Chrome'))
            return 'Chrome';
        if (str_contains($userAgent, 'Safari'))
            return 'Safari';
        if (str_contains($userAgent, 'Opera'))
            return 'Opera';
        return 'Other';
    }

    protected static function getOS(string $userAgent): string
    {
        if (preg_match('/windows|win32/i', $userAgent))
            return 'Windows';
        if (preg_match('/macintosh|mac os x/i', $userAgent))
            return 'macOS';
        if (preg_match('/linux/i', $userAgent))
            return 'Linux';
        if (preg_match('/iphone|ipad|ipod/i', $userAgent))
            return 'iOS';
        if (preg_match('/android/i', $userAgent))
            return 'Android';
        return 'Other';
    }

    protected static function getDeviceType(string $userAgent): string
    {
        if (preg_match('/mobile|phone|android|iphone/i', $userAgent)) {
            return 'mobile';
        }
        if (preg_match('/tablet|ipad/i', $userAgent)) {
            return 'tablet';
        }
        return 'desktop';
    }
}
