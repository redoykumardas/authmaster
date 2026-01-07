<?php

namespace Redoy\AuthMaster\Exceptions;

class TooManyAttemptsException extends AuthException
{
    public function __construct(string $message = 'Too many login attempts. Please try again later.')
    {
        parent::__construct($message, 429);
    }
}
