<?php

namespace Redoy\AuthMaster\DTOs;

use Redoy\AuthMaster\Http\Requests\ResetPasswordRequest;

readonly class PasswordResetData
{
    public function __construct(
        public string $email,
        public string $password,
        public string $token,
    ) {
    }

    public static function fromRequest(ResetPasswordRequest $request): self
    {
        return new self(
            email: $request->validated('email'),
            password: $request->validated('password'),
            token: $request->validated('token'),
        );
    }
}
