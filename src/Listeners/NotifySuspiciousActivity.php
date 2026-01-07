<?php

namespace Redoy\AuthMaster\Listeners;

use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Mail;
use Redoy\AuthMaster\Events\SuspiciousActivityDetected;

class NotifySuspiciousActivity
{
    public function handle(SuspiciousActivityDetected $event)
    {
        if (!config('authmaster.security.notify_on_suspicious', true)) {
            return;
        }

        // Logic to notify user or admin
        // For now, we alert via Log, but could send email here.
        Log::critical("SECURITY ALERT: [{$event->type}] detected for {$event->email} on IP {$event->ipAddress}");

        // if ($event->email) {
        //     Mail::to($event->email)->send(new \Redoy\AuthMaster\Mail\SuspiciousActivityMail($event));
        // }
    }
}
