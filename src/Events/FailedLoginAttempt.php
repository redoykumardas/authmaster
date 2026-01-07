<?php

namespace Redoy\AuthMaster\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class FailedLoginAttempt
{
    use Dispatchable, SerializesModels;

    public function __construct(
        public ?string $email,
        public string $ipAddress,
        public ?string $deviceId = null
    ) {
    }
}
