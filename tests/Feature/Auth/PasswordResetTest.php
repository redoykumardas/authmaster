<?php

namespace Redoy\AuthMaster\Tests\Feature\Auth;

use Redoy\AuthMaster\Services\AuthManager;

class PasswordResetTest extends AuthTestCase
{
    public function test_forgot_password_succeeds()
    {
        $auth = $this->createMock(AuthManager::class);
        $auth->method('sendPasswordResetLink')->willReturn(['success' => true]);

        $this->bindAuth($auth);
        $this->bindValidator();

        $this->postJson('/auth/password/email', [
            'email' => 'user@example.com',
        ])
            ->assertStatus(200)
            ->assertJsonFragment(['message' => 'Reset email sent']);
    }

    public function test_reset_password_succeeds()
    {
        $auth = $this->createMock(AuthManager::class);
        $auth->method('resetPassword')->willReturn(['success' => true]);

        $this->bindAuth($auth);
        $this->bindValidator();

        $this->postJson('/auth/password/reset', [
            'email' => 'user@example.com',
            'token' => 'tok',
            'password' => 'newpass',
        ])
            ->assertStatus(200)
            ->assertJsonFragment(['message' => 'Password reset']);
    }
}
