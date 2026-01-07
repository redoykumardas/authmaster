<?php

namespace Redoy\AuthMaster\Tests\Feature;

use Redoy\AuthMaster\Tests\TestCase;

class HelpersTest extends TestCase
{
    public function test_authmaster_device_id_uses_header_if_present()
    {
        $request = new \Illuminate\Http\Request();
        $request->headers->set('device_id', 'my-device-123');

        $deviceId = authmaster_device_id($request);
        $this->assertSame('my-device-123', $deviceId);
    }

    public function test_authmaster_token_response_defaults()
    {
        $resp = authmaster_token_response([]);
        $this->assertArrayHasKey('access_token', $resp);
        $this->assertArrayHasKey('token_type', $resp);
        $this->assertSame('Bearer', $resp['token_type']);
    }
}
