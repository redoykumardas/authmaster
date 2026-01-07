<?php

namespace Redoy\AuthMaster\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class AttachDeviceId
{
    public function handle(Request $request, Closure $next)
    {
        $deviceId = $request->header('device_id');
        if (empty($deviceId)) {
            $deviceId = hash('sha256', $request->ip() . '|' . $request->userAgent());
        }

        // attach to request for convenient access
        $request->attributes->set('device_id', (string) $deviceId);

        // also ensure header exists for other libraries
        $request->headers->set('device_id', (string) $deviceId);

        return $next($request);
    }
}
