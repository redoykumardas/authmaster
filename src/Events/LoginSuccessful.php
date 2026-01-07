<?php

namespace Redoy\AuthMaster\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class LoginSuccessful
{
    use Dispatchable, SerializesModels;

    public function __construct(
        public $user,
        public string $deviceId,
        public ?string $ipAddress = null
    ) {
    }
}
