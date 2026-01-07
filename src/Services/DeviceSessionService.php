<?php

namespace Redoy\AuthMaster\Services;

use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Cache;
use Redoy\AuthMaster\Contracts\DeviceSessionServiceInterface;

class DeviceSessionService implements DeviceSessionServiceInterface
{
    protected function userCacheKey($userId): string
    {
        return "authmaster:device_sessions:{$userId}";
    }

    public function createOrUpdateSession($user, string $deviceId, Request $request, $tokenId = null, array $tokenData = [], string $deviceName = null)
    {
        return $this->storeSession(
            $user,
            $deviceId,
            $tokenId,
            $tokenData,
            $deviceName,
            $request->ip(),
            $request->userAgent()
        );
    }

    public function createOrUpdateSessionFromData($user, string $deviceId, $tokenId = null, array $tokenData = [], ?string $deviceName = null)
    {
        return $this->storeSession(
            $user,
            $deviceId,
            $tokenId,
            $tokenData,
            $deviceName,
            null,
            null
        );
    }

    protected function storeSession($user, string $deviceId, $tokenId, array $tokenData, ?string $deviceName, ?string $ipAddress, ?string $userAgent)
    {
        $key = $this->userCacheKey($user->id);
        $sessions = Cache::get($key, []);

        $existing = $sessions[$deviceId] ?? null;

        $meta = array_merge($existing['meta'] ?? [], ['token' => $tokenData]);

        $sessions[$deviceId] = [
            'user_id' => $user->id,
            'device_id' => $deviceId,
            'device_name' => $deviceName,
            'ip_address' => $ipAddress,
            'user_agent' => $userAgent,
            'last_active_at' => Carbon::now()->toDateTimeString(),
            'token_id' => $tokenId,
            'meta' => $meta,
        ];

        $ttl = config('authmaster.device_session_ttl');
        if ($ttl) {
            Cache::put($key, $sessions, $ttl);
        } else {
            Cache::forever($key, $sessions);
        }

        return (object) $sessions[$deviceId];
    }

    public function enforceDeviceLimit($user): void
    {
        $limit = config('authmaster.max_devices_per_user');
        if (is_null($limit)) {
            return; // unlimited
        }

        $key = $this->userCacheKey($user->id);
        $sessions = Cache::get($key, []);

        if (count($sessions) <= $limit) {
            return;
        }

        // Sort by last_active_at desc
        uasort($sessions, function ($a, $b) {
            return strtotime($b['last_active_at']) <=> strtotime($a['last_active_at']);
        });

        $kept = array_slice($sessions, 0, $limit, true);
        $toRemove = array_slice($sessions, $limit, null, true);

        foreach ($toRemove as $s) {
            if (!empty($s['token_id']) && method_exists($user, 'tokens')) {
                try {
                    $user->tokens()->where('id', $s['token_id'])->delete();
                } catch (\Throwable $e) {
                    // ignore
                }
            }
        }

        // Persist the kept sessions
        $ttl = config('authmaster.device_session_ttl');
        if ($ttl) {
            Cache::put($key, $kept, $ttl);
        } else {
            Cache::forever($key, $kept);
        }
    }

    public function invalidateSession($user, string $deviceId): void
    {
        $key = $this->userCacheKey($user->id);
        $sessions = Cache::get($key, []);
        $session = $sessions[$deviceId] ?? null;
        if (!$session) {
            return;
        }

        if (!empty($session['token_id']) && method_exists($user, 'tokens')) {
            try {
                $user->tokens()->where('id', $session['token_id'])->delete();
            } catch (\Throwable $e) {
                // ignore
            }
        }

        unset($sessions[$deviceId]);

        $ttl = config('authmaster.device_session_ttl');
        if ($ttl) {
            Cache::put($key, $sessions, $ttl);
        } else {
            Cache::forever($key, $sessions);
        }
    }

    public function invalidateAllSessions($user): void
    {
        $key = $this->userCacheKey($user->id);
        $sessions = Cache::get($key, []);
        foreach ($sessions as $session) {
            if (!empty($session['token_id']) && method_exists($user, 'tokens')) {
                try {
                    $user->tokens()->where('id', $session['token_id'])->delete();
                } catch (\Throwable $e) {
                    // ignore
                }
            }
        }

        Cache::forget($key);
    }

    public function getActiveSessions($user)
    {
        $key = $this->userCacheKey($user->id);
        $sessions = Cache::get($key, []);

        uasort($sessions, function ($a, $b) {
            return strtotime($b['last_active_at']) <=> strtotime($a['last_active_at']);
        });

        return collect(array_values($sessions));
    }
}
