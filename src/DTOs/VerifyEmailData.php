<?php

namespace Redoy\AuthMaster\DTOs;

use Redoy\AuthMaster\Http\Requests\VerifyEmailRequest;

readonly class VerifyEmailData
{
    public function __construct(
        public ?string $email,
        public ?string $code,
        public ?string $token,
        public string $method,
        public string $deviceId,
        public ?string $deviceName,
        public string $ipAddress,
        public ?string $userAgent,
    ) {
    }

    public static function fromRequest(VerifyEmailRequest $request): self
    {
        $method = config('authmaster.registration.email_verification', 'none');
        $deviceId = $request->header('device_id')
            ?? $request->header('X-Device-Id')
            ?? $request->header('Device-Id')
            ?? hash('sha256', (string) $request->ip() . '|' . (string) $request->userAgent());

        $deviceName = $request->input('device_name')
            ?? $request->header('X-Device-Name')
            ?? $request->header('Device-Name');

        return new self(
            email: $request->validated('email'),
            code: $request->validated('code'),
            token: $request->validated('token'),
            method: $method,
            deviceId: $deviceId,
            deviceName: $deviceName,
            ipAddress: $request->ip() ?? '127.0.0.1',
            userAgent: $request->userAgent(),
        );
    }
}
