<?php

namespace Redoy\AuthMaster\Listeners;

use Illuminate\Support\Facades\Log;
use Redoy\AuthMaster\Events\LoginSuccessful;
use Redoy\AuthMaster\Events\LogoutSuccessful;
use Redoy\AuthMaster\Events\FailedLoginAttempt;
use Redoy\AuthMaster\Events\SuspiciousActivityDetected;

class LogSecurityActivity
{
    public function handle($event)
    {
        if ($event instanceof LoginSuccessful) {
            Log::info("AuthMaster: Login successful for user {$event->user->email} from IP {$event->ipAddress} (Device: {$event->deviceId})");
        } elseif ($event instanceof LogoutSuccessful) {
            Log::info("AuthMaster: Logout successful for user {$event->user->email} (Device: {$event->deviceId})");
        } elseif ($event instanceof FailedLoginAttempt) {
            Log::warning("AuthMaster: Failed login attempt for email {$event->email} from IP {$event->ipAddress}");
        } elseif ($event instanceof SuspiciousActivityDetected) {
            Log::alert("AuthMaster: Suspicious activity detected! Type: {$event->type}, Email: {$event->email}, IP: {$event->ipAddress}", $event->metadata);
        }
    }
}
