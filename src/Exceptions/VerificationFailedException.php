<?php

namespace Redoy\AuthMaster\Exceptions;

class VerificationFailedException extends AuthException
{
    public function __construct(string $message = 'Verification failed')
    {
        parent::__construct($message, 422);
    }
}
