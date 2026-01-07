<?php

namespace Redoy\AuthMaster\Exceptions;

class InvalidCredentialsException extends AuthException
{
    public function __construct(string $message = 'Invalid credentials')
    {
        parent::__construct($message, 401);
    }
}
