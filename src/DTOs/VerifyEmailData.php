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
    ) {
    }

    public static function fromRequest(VerifyEmailRequest $request): self
    {
        $method = config('authmaster.registration.email_verification', 'none');
        $deviceId = $request->header('device_id')
            ?? hash('sha256', $request->ip() . '|' . $request->userAgent());

        return new self(
            email: $request->validated('email'),
            code: $request->validated('code'),
            token: $request->validated('token'),
            method: $method,
            deviceId: $deviceId,
            deviceName: $request->input('device_name'),
        );
    }
}
