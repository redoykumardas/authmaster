<?php

namespace Redoy\AuthMaster\Services;

use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Redoy\AuthMaster\Contracts\DeviceSessionServiceInterface;
use Redoy\AuthMaster\Models\DeviceSession;

class DeviceSessionService implements DeviceSessionServiceInterface
{
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
        $session = DeviceSession::updateOrCreate(
            ['user_id' => $user->id, 'device_id' => $deviceId],
            [
                'device_name' => $deviceName,
                'ip_address' => $ipAddress,
                'user_agent' => $userAgent,
                'last_active_at' => Carbon::now(),
                'token_id' => $tokenId,
                'meta' => ['token' => $tokenData],
            ]
        );

        return $session;
    }

    public function enforceDeviceLimit($user): void
    {
        $limit = config('authmaster.max_devices_per_user');
        if (is_null($limit)) {
            return; // unlimited
        }

        $sessions = DeviceSession::where('user_id', $user->id)
            ->orderBy('last_active_at', 'desc')
            ->get();

        if ($sessions->count() <= $limit) {
            return;
        }

        $toRemove = $sessions->slice($limit);

        foreach ($toRemove as $session) {
            if (!empty($session->token_id) && method_exists($user, 'tokens')) {
                try {
                    $user->tokens()->where('id', $session->token_id)->delete();
                } catch (\Throwable $e) {
                    // ignore
                }
            }
            $session->delete();
        }
    }

    public function invalidateSession($user, string $deviceId): void
    {
        $session = DeviceSession::where('user_id', $user->id)
            ->where('device_id', $deviceId)
            ->first();

        if (!$session) {
            return;
        }

        if (!empty($session->token_id) && method_exists($user, 'tokens')) {
            try {
                $user->tokens()->where('id', $session->token_id)->delete();
            } catch (\Throwable $e) {
                // ignore
            }
        }

        $session->delete();
    }

    public function invalidateAllSessions($user): void
    {
        $sessions = DeviceSession::where('user_id', $user->id)->get();

        foreach ($sessions as $session) {
            if (!empty($session->token_id) && method_exists($user, 'tokens')) {
                try {
                    $user->tokens()->where('id', $session->token_id)->delete();
                } catch (\Throwable $e) {
                    // ignore
                }
            }
            $session->delete();
        }
    }

    public function getActiveSessions($user)
    {
        return DeviceSession::where('user_id', $user->id)
            ->orderBy('last_active_at', 'desc')
            ->get();
    }
}
