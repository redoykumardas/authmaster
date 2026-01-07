<?php

namespace Redoy\AuthMaster\Services;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Mail;
use Redoy\AuthMaster\Contracts\SecurityServiceInterface;

class SecurityService implements SecurityServiceInterface
{
    protected function attemptsKey(?string $email, string $ip)
    {
        return 'authmaster_attempts:' . ($email ?? 'guest') . ':' . $ip;
    }

    public function allowLoginAttempt(?string $email, string $ip): bool
    {
        $key = $this->attemptsKey($email, $ip);
        $attempts = Cache::get($key, 0);
        $max = config('authmaster.security.max_login_attempts', 5);
        if ($max <= 0) {
            return true;
        }
        return $attempts < $max;
    }

    public function recordFailedAttempt(?string $email, string $ip): void
    {
        $key = $this->attemptsKey($email, $ip);
        $ttl = config('authmaster.security.lockout_duration_minutes', 15) * 60;
        $attempts = Cache::increment($key);
        Cache::put($key, $attempts, $ttl);

        // If exceeds threshold, optionally notify user
        $max = config('authmaster.security.max_login_attempts', 5);
        if ($attempts >= $max && config('authmaster.security.notify_on_suspicious', true)) {
            try {
                // TODO: send notification email to user if email provided
                // Mail::to($email)->send(new SuspiciousLoginMail(...));
            } catch (\Throwable $e) {
                Log::error('AuthMaster: failed to send suspicious login notification: ' . $e->getMessage());
            }
        }
    }

    public function clearFailedAttempts(string $email): void
    {
        // Clear attempts for all ips for this email
        // This is a simple implementation: clears keys matching pattern - requires cache store supporting tags or iteration.
        // For simplicity store only exact email + ip keys; callers can clear exact key if needed. We'll clear common patterns.
        // Not implemented complex scan here.
    }
}
