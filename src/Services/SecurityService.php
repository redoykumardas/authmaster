<?php

namespace Redoy\AuthMaster\Services;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Mail;
use Redoy\AuthMaster\Contracts\SecurityServiceInterface;
use Redoy\AuthMaster\Events\FailedLoginAttempt;
use Redoy\AuthMaster\Events\SuspiciousActivityDetected;

class SecurityService implements SecurityServiceInterface
{
    public function allowLoginAttempt(?string $email, string $ip): bool
    {
        $max = config('authmaster.security.max_login_attempts', 5);
        if ($max <= 0) {
            return true;
        }

        $attempt = DB::table('authmaster_login_attempts')
            ->where('email', $email)
            ->where('ip_address', $ip)
            ->first();

        if (!$attempt) {
            return true;
        }

        $lockoutMinutes = config('authmaster.security.lockout_duration_minutes', 15);
        $isLockedOut = $attempt->attempts >= $max &&
            $attempt->last_attempt_at > now()->subMinutes($lockoutMinutes);

        return !$isLockedOut;
    }

    public function recordFailedAttempt(?string $email, string $ip): void
    {
        DB::table('authmaster_login_attempts')->updateOrInsert(
            ['email' => $email, 'ip_address' => $ip],
            [
                'attempts' => DB::raw('attempts + 1'),
                'last_attempt_at' => now(),
                'updated_at' => now(),
            ]
        );

        $attempt = DB::table('authmaster_login_attempts')
            ->where('email', $email)
            ->where('ip_address', $ip)
            ->first();

        $attempts = $attempt->attempts ?? 0;

        event(new FailedLoginAttempt($email, $ip));

        $max = config('authmaster.security.max_login_attempts', 5);
        if ($attempts >= $max) {
            event(new SuspiciousActivityDetected(
                type: 'account_lockout',
                email: $email,
                ipAddress: $ip,
                metadata: ['attempts' => $attempts]
            ));
        }
    }

    public function clearFailedAttempts(string $email): void
    {
        DB::table('authmaster_login_attempts')->where('email', $email)->delete();
    }
}
