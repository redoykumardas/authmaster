<?php

namespace Redoy\AuthMaster\DTOs;

use Redoy\AuthMaster\Http\Requests\LoginRequest;

readonly class LoginData
{
    public function __construct(
        public string $email,
        public string $password,
        public string $deviceId,
        public ?string $deviceName,
        public string $ipAddress,
        public ?string $userAgent,
    ) {
    }

    public static function fromRequest(LoginRequest $request): self
    {
        $deviceId = $request->header('device_id')
            ?? $request->header('X-Device-Id')
            ?? $request->header('Device-Id')
            ?? authmaster_device_id($request);

        $deviceName = $request->input('device_name')
            ?? $request->header('X-Device-Name')
            ?? $request->header('Device-Name');

        return new self(
            email: $request->validated('email'),
            password: $request->validated('password'),
            deviceId: $deviceId,
            deviceName: $deviceName,
            ipAddress: $request->ip() ?? '127.0.0.1',
            userAgent: $request->userAgent(),
        );
    }
}
