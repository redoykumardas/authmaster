<?php

namespace Redoy\AuthMaster\DTOs;

readonly class AuthResult
{
    public function __construct(
        public mixed $user,
        public ?array $token = null,
        public ?string $message = null,
        public bool $emailVerificationRequired = false,
        public ?string $emailVerificationMethod = null,
        public bool $pendingRegistration = false,
        public ?string $devVerificationUrl = null,
        public ?string $devToken = null,
    ) {
    }

    public function toArray(): array
    {
        $data = [
            'user' => $this->user,
        ];

        if ($this->token) {
            $data['token'] = $this->token;
        }

        if ($this->emailVerificationRequired) {
            $data['email_verification_required'] = true;
            $data['email_verification_method'] = $this->emailVerificationMethod;
        }

        if ($this->pendingRegistration) {
            $data['pending_registration'] = true;
        }

        // Dev info (hidden in production)
        if ($this->devVerificationUrl && !app()->isProduction()) {
            $data['dev_verification_url'] = $this->devVerificationUrl;
            $data['dev_token'] = $this->devToken;
        }

        return $data;
    }
}
