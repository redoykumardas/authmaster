<?php

namespace Redoy\AuthMaster\Tests\Unit;

use Redoy\AuthMaster\Tests\TestCase;
use Redoy\AuthMaster\Services\DeviceSessionService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

class DeviceSessionServiceTest extends TestCase
{
    public function test_create_or_update_session_and_get_active_sessions()
    {
        $svc = new DeviceSessionService();
        $user = new \stdClass();
        $user->id = 5;

        $req = Request::create('/','GET');
        $req->server->set('REMOTE_ADDR', '127.0.0.1');
        $req->headers->set('User-Agent', 'phpunit');

        $s1 = $svc->createOrUpdateSession($user, 'dev-1', $req, null, ['token' => 't1']);
        $this->assertEquals('dev-1', $s1->device_id);

        $s2 = $svc->createOrUpdateSession($user, 'dev-2', $req, null, ['token' => 't2']);
        $this->assertEquals('dev-2', $s2->device_id);

        $active = $svc->getActiveSessions($user);
        $this->assertCount(2, $active);
    }

    public function test_enforce_device_limit_trims_sessions()
    {
        $svc = new DeviceSessionService();
        $user = new \stdClass();
        $user->id = 6;

        $req = Request::create('/','GET');
        $req->headers->set('User-Agent', 'phpunit');

        // set limit to 1
        config()->set('authmaster.max_devices_per_user', 1);

        $svc->createOrUpdateSession($user, 'a', $req, null, ['token' => 't1']);
        // sleep 1 second to ensure different second-level timestamps
        sleep(1);
        $svc->createOrUpdateSession($user, 'b', $req, null, ['token' => 't2']);

        $svc->enforceDeviceLimit($user);

        $sessions = \Redoy\AuthMaster\Models\DeviceSession::where('user_id', $user->id)->get();
        $this->assertCount(1, $sessions);
        $this->assertEquals('b', $sessions->first()->device_id);
    }

    public function test_invalidate_session_and_invalidate_all()
    {
        $svc = new DeviceSessionService();
        $user = new \stdClass();
        $user->id = 7;

        $req = Request::create('/','GET');
        $req->headers->set('User-Agent', 'phpunit');

        $svc->createOrUpdateSession($user, 'x', $req, null, ['token' => 't1']);
        $svc->createOrUpdateSession($user, 'y', $req, null, ['token' => 't2']);

        $svc->invalidateSession($user, 'x');
        $this->assertDatabaseMissing('authmaster_device_sessions', [
            'user_id' => 7,
            'device_id' => 'x'
        ]);

        $svc->invalidateAllSessions($user);
        $this->assertDatabaseMissing('authmaster_device_sessions', [
            'user_id' => 7
        ]);
    }
}
