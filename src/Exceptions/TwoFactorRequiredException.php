<?php

namespace Redoy\AuthMaster\Exceptions;

class TwoFactorRequiredException extends AuthException
{
    public function __construct(
        string $message = 'Two-factor authentication required',
        public ?string $tempToken = null,
        public ?string $devOtp = null
    ) {
        $payload = [
            'requires_2fa' => true,
            'temp_token' => $tempToken,
        ];
        
        if ($devOtp && !app()->isProduction()) {
            $payload['dev_otp'] = $devOtp;
        }
        
        parent::__construct($message, 403, $payload);
    }
}
