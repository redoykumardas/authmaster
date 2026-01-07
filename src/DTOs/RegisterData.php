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
    ) {
    }

    public static function fromRequest(RegisterRequest $request): self
    {
        $deviceId = $request->header('device_id')
            ?? hash('sha256', $request->ip() . '|' . $request->userAgent());

        return new self(
            name: $request->validated('name'),
            email: $request->validated('email'),
            password: $request->validated('password'),
            deviceId: $deviceId,
            deviceName: $request->validated('device_name'),
            ipAddress: $request->ip() ?? '127.0.0.1',
        );
    }
}
