<?php

namespace Redoy\AuthMaster\Tests\Feature\Auth;

use Redoy\AuthMaster\Contracts\AuthManagerInterface;
use Redoy\AuthMaster\DTOs\AuthResult;
use Redoy\AuthMaster\Services\AuthManager;

class PasswordResetTest extends AuthTestCase
{
    public function test_forgot_password_succeeds()
    {
        $auth = $this->createMock(AuthManagerInterface::class);
        $auth->method('sendPasswordResetLink')->willReturn(new AuthResult(message: 'Reset email sent'));

        $this->bindAuth($auth);

        $this->postJson('/api/auth/password/email', [
            'email' => 'user@example.com',
        ])
            ->assertStatus(200)
            ->assertJsonFragment(['message' => 'Reset email sent']);
    }

    public function test_reset_password_succeeds()
    {
        $auth = $this->createMock(AuthManagerInterface::class);
        $auth->method('resetPasswordWithData')->willReturn(new AuthResult(message: 'Password reset'));

        $this->bindAuth($auth);

        $this->postJson('/api/auth/password/reset', [
            'email' => 'user@example.com',
            'token' => 'tok',
            'password' => 'newpassword',
            'password_confirmation' => 'newpassword',
        ])
            ->assertStatus(200)
            ->assertJsonFragment(['message' => 'Password reset']);
    }
}
