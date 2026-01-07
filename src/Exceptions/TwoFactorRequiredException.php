<?php

namespace Redoy\AuthMaster\Exceptions;

class TwoFactorRequiredException extends AuthException
{
    public function __construct(string $message = 'Two-factor authentication required')
    {
        parent::__construct($message, 403);
    }
}
