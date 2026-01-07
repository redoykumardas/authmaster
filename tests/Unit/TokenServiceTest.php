<?php

namespace Redoy\AuthMaster\Tests\Unit;

use Redoy\AuthMaster\Tests\TestCase;
use Redoy\AuthMaster\Services\TokenService;

class TokenServiceTest extends TestCase
{
    public function test_create_token_for_user_without_createToken_method_returns_token()
    {
        $svc = new TokenService();

        $user = new \stdClass();
        $result = $svc->createTokenForUser($user, 'device-1');

        $this->assertArrayHasKey('access_token', $result);
        $this->assertNotEmpty($result['access_token']);
        $this->assertSame('Bearer', $result['token_type']);
        $this->assertArrayHasKey('expires_at', $result);
    }
}
