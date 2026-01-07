<?php

namespace Redoy\AuthMaster\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Redoy\AuthMaster\Models\DeviceSession;
use Redoy\AuthMaster\Contracts\AuthManagerInterface;

class TrackDeviceActivity
{
    public function __construct(
        protected AuthManagerInterface $authManager
    ) {
    }

    public function handle(Request $request, Closure $next)
    {
        $user = $request->user();

        if ($user) {
            $deviceId = $this->authManager->extractDeviceId($request);

            DeviceSession::where('user_id', $user->id)
                ->where('device_id', $deviceId)
                ->update([
                    'last_active_at' => now(),
                    'ip_address' => $request->ip(),
                    'user_agent' => $request->userAgent(),
                ]);
        }

        return $next($request);
    }
}
