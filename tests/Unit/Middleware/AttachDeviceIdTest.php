<?php

namespace Redoy\AuthMaster\Tests\Unit\Middleware;

use Redoy\AuthMaster\Tests\TestCase;
use Redoy\AuthMaster\Http\Middleware\AttachDeviceId;
use Illuminate\Http\Request;

class AttachDeviceIdTest extends TestCase
{
    public function test_attaches_device_id_header_and_attribute_when_missing()
    {
        $middleware = new AttachDeviceId();

        $request = Request::create('/test', 'GET');
        // ensure no device_id header
        $this->assertNull($request->header('device_id'));

        $response = $middleware->handle($request, function ($req) {
            return response('ok');
        });

        $this->assertEquals('ok', $response->getContent());
        $this->assertNotEmpty($request->headers->get('device_id'));
        $this->assertNotEmpty($request->attributes->get('device_id'));
    }

    public function test_keeps_existing_device_id()
    {
        $middleware = new AttachDeviceId();

        $request = Request::create('/test', 'GET');
        $request->headers->set('device_id', 'existing-id');

        $middleware->handle($request, function ($req) {
            return response('ok');
        });

        $this->assertSame('existing-id', $request->headers->get('device_id'));
        $this->assertSame('existing-id', $request->attributes->get('device_id'));
    }
}
