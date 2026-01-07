<?php

namespace Redoy\AuthMaster\Services;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Redoy\AuthMaster\Contracts\SecurityServiceInterface;
use Redoy\AuthMaster\Events\FailedLoginAttempt;
use Redoy\AuthMaster\Events\SuspiciousActivityDetected;

class SecurityService implements SecurityServiceInterface
{
    public function allowLoginAttempt(?string $email, string $ip, ?string $deviceId = null): bool
    {
        // Check global email/IP lockout
        if (
            !$this->isAllowedByAttempts('authmaster_login_attempts', [
                'email' => $email,
                'ip_address' => $ip
            ], config('authmaster.security.max_login_attempts', 5), config('authmaster.security.lockout_duration_minutes', 15))
        ) {
            return false;
        }

        // Check device-specific lockout
        if ($deviceId) {
            if (
                !$this->isAllowedByAttempts('authmaster_login_attempts', [
                    'device_id' => $deviceId
                ], config('authmaster.security.max_login_attempts_per_device', 10), config('authmaster.security.device_lockout_duration_minutes', 60))
            ) {
                return false;
            }
        }

        return true;
    }

    protected function isAllowedByAttempts(string $table, array $where, int $max, int $lockoutMinutes): bool
    {
        if ($max <= 0) {
            return true;
        }

        $query = DB::table($table);
        foreach ($where as $column => $value) {
            if (is_null($value)) {
                $query->whereNull($column);
            } else {
                $query->where($column, $value);
            }
        }

        $attempt = $query->first();

        if (!$attempt) {
            return true;
        }

        $isLockedOut = $attempt->attempts >= $max &&
            $attempt->last_attempt_at > now()->subMinutes($lockoutMinutes);

        return !$isLockedOut;
    }

    public function recordFailedAttempt(?string $email, string $ip, ?string $deviceId = null): void
    {
        // Update or insert record for email/IP combination
        $this->updateAttemptCount('authmaster_login_attempts', ['email' => $email, 'ip_address' => $ip]);

        // Update or insert record for device-only if deviceId exists
        if ($deviceId) {
            $this->updateAttemptCount('authmaster_login_attempts', ['device_id' => $deviceId]);
        }

        event(new FailedLoginAttempt($email, $ip));

        // Aggregate check for suspicious activity notifications
        $totalAttempts = DB::table('authmaster_login_attempts')
            ->where('ip_address', $ip)
            ->where('last_attempt_at', '>', now()->subMinutes(5))
            ->sum('attempts');

        $max = config('authmaster.security.max_login_attempts', 5);
        if ($totalAttempts >= $max * 2) {
            event(new SuspiciousActivityDetected(
                type: 'high_frequency_failures',
                email: $email,
                ipAddress: $ip,
                metadata: ['total_recent_attempts' => $totalAttempts, 'device_id' => $deviceId]
            ));
        }
    }

    protected function updateAttemptCount(string $table, array $where): void
    {
        $query = DB::table($table);
        foreach ($where as $column => $value) {
            if (is_null($value)) {
                $query->whereNull($column);
            } else {
                $query->where($column, $value);
            }
        }

        if ($query->exists()) {
            $query->increment('attempts', 1, [
                'last_attempt_at' => now(),
                'updated_at' => now(),
            ]);
        } else {
            DB::table($table)->insert(array_merge($where, [
                'attempts' => 1,
                'last_attempt_at' => now(),
                'created_at' => now(),
                'updated_at' => now(),
            ]));
        }
    }

    public function clearFailedAttempts(string $email, ?string $deviceId = null): void
    {
        DB::table('authmaster_login_attempts')->where('email', $email)->delete();
        if ($deviceId) {
            DB::table('authmaster_login_attempts')->where('device_id', $deviceId)->delete();
        }
    }

    public function allowRegistrationAttempt(string $ip, ?string $deviceId = null): bool
    {
        $max = config('authmaster.security.max_registration_attempts_per_device', 3);
        $lockout = config('authmaster.security.device_lockout_duration_minutes', 60);

        return $this->isAllowedByAttempts('authmaster_registration_attempts', [
            'ip_address' => $ip,
            'device_id' => $deviceId
        ], $max, $lockout);
    }

    public function recordRegistrationAttempt(string $ip, ?string $deviceId = null): void
    {
        $this->updateAttemptCount('authmaster_registration_attempts', [
            'ip_address' => $ip,
            'device_id' => $deviceId
        ]);
    }
}
