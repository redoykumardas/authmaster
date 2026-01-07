<?php

namespace Redoy\AuthMaster\Tests\Feature\Auth;

use Redoy\AuthMaster\Contracts\AuthManagerInterface;
use Redoy\AuthMaster\DTOs\AuthResult;
use Redoy\AuthMaster\Services\AuthManager;

class LoginTest extends AuthTestCase
{
    public function test_login_success_returns_200()
    {
        $auth = $this->createMock(AuthManagerInterface::class);
        $auth->method('loginWithData')->willReturn(new AuthResult(
            user: (object) ['id' => 1, 'name' => 'Test', 'email' => 'test@example.com'],
            token: ['token' => 'abc'],
            message: 'Logged in'
        ));

        $this->bindAuth($auth);

        $this->postJson('/api/auth/login', [
            'email' => 'test@example.com',
            'password' => 'secret',
        ])
            ->assertStatus(200)
            ->assertJsonFragment(['message' => 'Logged in']);
    }

    public function test_login_failure_returns_401()
    {
        $auth = $this->createMock(AuthManagerInterface::class);
        $auth->method('loginWithData')->willThrowException(new \Redoy\AuthMaster\Exceptions\InvalidCredentialsException('Invalid credentials'));

        $this->bindAuth($auth);

        $this->postJson('/api/auth/login', [
            'email' => 'bad@example.com',
            'password' => 'wrong',
        ])
            ->assertStatus(401)
            ->assertJsonFragment(['message' => 'Invalid credentials']);
    }
}
