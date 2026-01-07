<?php

namespace Redoy\AuthMaster\DTOs;

use Redoy\AuthMaster\Http\Requests\RegisterRequest;

readonly class RegisterData
{
    public function __construct(
        public string $name,
        public string $email,
        public string $password,
        public string $deviceId,
        public ?string $deviceName,
        public string $ipAddress,
        public ?string $userAgent,
    ) {
    }

    public static function fromRequest(RegisterRequest $request): self
    {
        $deviceId = $request->header('device_id')
            ?? $request->header('X-Device-Id')
            ?? $request->header('Device-Id')
            ?? hash('sha256', (string) $request->ip() . '|' . (string) $request->userAgent());

        $deviceName = $request->input('device_name')
            ?? $request->header('X-Device-Name')
            ?? $request->header('Device-Name');

        return new self(
            name: $request->validated('name'),
            email: $request->validated('email'),
            password: $request->validated('password'),
            deviceId: $deviceId,
            deviceName: $deviceName,
            ipAddress: $request->ip() ?? '127.0.0.1',
            userAgent: $request->userAgent(),
        );
    }
}
