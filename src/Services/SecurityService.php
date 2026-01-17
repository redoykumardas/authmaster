<?php

namespace Redoy\AuthMaster\Services;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Redoy\AuthMaster\Exceptions\TooManyAttemptsException;
use Redoy\AuthMaster\Contracts\SecurityServiceInterface;
use Redoy\AuthMaster\Events\FailedLoginAttempt;
use Redoy\AuthMaster\Events\SuspiciousActivityDetected;

class SecurityService implements SecurityServiceInterface
{
    public function __construct(
        protected Request $request
    ) {}

    public function allowLoginAttempt(?string $email, string $ip, ?string $deviceId = null): void
    {
        // Check global email/IP lockout
        if (
            !$this->isAllowedByAttempts('authmaster_login_attempts', [
                'email' => $email,
                'ip_address' => $ip
            ], config('authmaster.security.max_login_attempts', 5), config('authmaster.security.lockout_duration_minutes', 15))
        ) {
            throw new TooManyAttemptsException('Too many login attempts. Please try again later.');
        }

        // Check device-specific lockout
        if ($deviceId) {
            if (
                !$this->isAllowedByAttempts('authmaster_login_attempts', [
                    'device_id' => $deviceId
                ], config('authmaster.security.max_login_attempts_per_device', 10), config('authmaster.security.device_lockout_duration_minutes', 60))
            ) {
                throw new TooManyAttemptsException('Too many login attempts from this device. Please try again later.');
            }
        }
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

        $stats = $query->selectRaw('SUM(attempts) as total_attempts, MAX(last_attempt_at) as last_at')->first();

        if (!$stats || $stats->total_attempts == 0) {
            return true;
        }

        $lastAttemptAt = Carbon::parse($stats->last_at);
        $isLockedOut = $stats->total_attempts >= $max &&
            $lastAttemptAt->isAfter(now()->subMinutes($lockoutMinutes));

        return !$isLockedOut;
    }

    public function recordFailedAttempt(?string $email, string $ip, ?string $deviceId = null): void
    {
        // Update or insert record for cell (email, ip)
        $this->updateAttemptCount('authmaster_login_attempts', ['email' => $email, 'ip_address' => $ip]);

        // Update or insert record for device-only tracking across all IPs/accounts
        if ($deviceId) {
            $this->updateAttemptCount('authmaster_login_attempts', ['device_id' => $deviceId, 'email' => null]);
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

    public function allowRegistrationAttempt(?string $ip = null, ?string $deviceId = null): void
    {
        $ip = $ip ?? $this->request->ip();
        $deviceId = $deviceId ?? $this->request->header('device_id') ?? $this->request->header('X-Device-Id');

        $max = config('authmaster.security.max_registration_attempts_per_device', 3);
        $lockout = config('authmaster.security.device_lockout_duration_minutes', 60);

        if (!$this->isAllowedByAttempts('authmaster_registration_attempts', [
            'ip_address' => $ip,
            'device_id' => $deviceId
        ], $max, $lockout)) {
            throw new TooManyAttemptsException('Too many registration attempts. Please try again later.');
        }
    }

    public function recordRegistrationAttempt(?string $ip = null, ?string $deviceId = null): void
    {
        $ip = $ip ?? $this->request->ip();
        $deviceId = $deviceId ?? $this->request->header('device_id') ?? $this->request->header('X-Device-Id');

        $this->updateAttemptCount('authmaster_registration_attempts', [
            'ip_address' => $ip,
            'device_id' => $deviceId
        ]);
    }
}
