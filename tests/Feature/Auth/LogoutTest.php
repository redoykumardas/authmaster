<?php

namespace Redoy\AuthMaster\Tests\Feature\Auth;

use Redoy\AuthMaster\Services\AuthManager;

class LogoutTest extends AuthTestCase
{
    public function test_logout_endpoints()
    {
        $this->bindAuth($this->createMock(AuthManager::class));

        $this->postJson('/auth/logout')
            ->assertStatus(200)
            ->assertJsonFragment(['message' => 'Logged out']);

        $this->postJson('/auth/logout/all')
            ->assertStatus(200)
            ->assertJsonFragment(['message' => 'Logged out from all devices']);
    }
}
