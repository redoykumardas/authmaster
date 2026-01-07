<?php

namespace Redoy\AuthMaster\Tests\Feature\Auth;

use Redoy\AuthMaster\Services\AuthManager;

class LoginTest extends AuthTestCase
{
    public function test_login_success_returns_200()
    {
        $auth = $this->createMock(AuthManager::class);
        $auth->method('login')->willReturn([
            'success' => true,
            'data' => ['token' => 'abc'],
        ]);

        $this->bindAuth($auth);
        $this->bindValidator();

        $this->postJson('/auth/login', [
            'email' => 'test@example.com',
            'password' => 'secret',
        ])
            ->assertStatus(200)
            ->assertJsonFragment(['message' => 'Logged in']);
    }

    public function test_login_failure_returns_401()
    {
        $auth = $this->createMock(AuthManager::class);
        $auth->method('login')->willReturn([
            'success' => false,
            'message' => 'Invalid credentials',
        ]);

        $this->bindAuth($auth);
        $this->bindValidator();

        $this->postJson('/auth/login', [
            'email' => 'bad@example.com',
            'password' => 'wrong',
        ])
            ->assertStatus(401)
            ->assertJsonFragment(['message' => 'Invalid credentials']);
    }
}
