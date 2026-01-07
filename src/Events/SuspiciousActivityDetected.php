<?php

namespace Redoy\AuthMaster\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class SuspiciousActivityDetected
{
    use Dispatchable, SerializesModels;

    public function __construct(
        public string $type,
        public ?string $email = null,
        public ?string $ipAddress = null,
        public array $metadata = []
    ) {
    }
}
