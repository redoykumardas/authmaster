<?php

use Illuminate\Http\Request;

if (!function_exists('authmaster_device_id')) {
    function authmaster_device_id(Request $request = null): string
    {
        if (is_null($request)) {
            $request = request();
        }

        $deviceId = $request->header('device_id');
        if (!empty($deviceId)) {
            return (string) $deviceId;
        }

        return hash('sha256', $request->ip() . '|' . $request->userAgent());
    }
}

if (!function_exists('authmaster_token_response')) {
    function authmaster_token_response(array $tokenData = []): array
    {
        return [
            'access_token' => $tokenData['access_token'] ?? null,
            'token_type' => $tokenData['token_type'] ?? 'Bearer',
            'expires_at' => $tokenData['expires_at'] ?? null,
        ];
    }
}
