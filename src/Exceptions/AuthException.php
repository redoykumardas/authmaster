<?php

namespace Redoy\AuthMaster\Exceptions;

use Exception;

use Illuminate\Http\JsonResponse;
use Redoy\CoreModule\Facades\CoreResponse;

class AuthException extends Exception
{
    protected int $statusCode = 400;
    protected array $errors = [];

    public function __construct(
        string $message = 'Authentication error',
        int $statusCode = 400,
        array $errors = []
    ) {
        parent::__construct($message);
        $this->statusCode = $statusCode;
        $this->errors = $errors;
    }

    public function getStatusCode(): int
    {
        return $this->statusCode;
    }

    public function getErrors(): array
    {
        return $this->errors;
    }

    public function render()
    {
        return CoreResponse::errorResponse(
            $this->errors,
            $this->statusCode,
            $this->getMessage()
        );
    }
}
